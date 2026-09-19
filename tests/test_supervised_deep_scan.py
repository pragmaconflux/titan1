"""Supervision must preserve downstream artifact checks and fail closed."""

from hashlib import sha256
import io
import json
from pathlib import Path
import threading
import zipfile

import pytest

from titan_decoder import cli
from titan_decoder.config import Config
from titan_decoder.core.deep_scan import DeepScanner
from titan_decoder.core.quarantine import QuarantineVault


def test_nested_payload_is_still_scanned_and_quarantined(tmp_path):
    payload = b"a unique malicious fixture payload"
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
        stream.writestr("child.txt", payload)
    source = tmp_path / "sample.zip"
    source.write_bytes(archive.getvalue())
    hashes = tmp_path / "hashes.txt"
    hashes.write_text(sha256(archive.getvalue()).hexdigest() + " archive fixture\n")
    config = Config(tmp_path / "absent.json")
    config.set("malicious_hashes_path", str(hashes))
    events = []
    vault = QuarantineVault(tmp_path / "vault")
    summary = DeepScanner(
        config, supervised=True, progress_callback=events.append
    ).scan(
        source,
        reports_dir=tmp_path / "reports",
        quarantine=vault,
        quarantine_verdicts={"MALICIOUS"},
    )
    assert summary["error_count"] == 0
    assert summary["results"][0]["verdict"] == "MALICIOUS"
    report = json.loads(Path(summary["results"][0]["report_path"]).read_text())
    assert any(
        node["sha256"] == sha256(payload).hexdigest() for node in report["nodes"]
    )
    assert report["static_analysis"]["completed"]
    assert payload.decode() in report["interesting_strings"]
    assert summary["results"][0]["quarantine"] is not None
    assert source.exists()
    assert events[0]["stage"] == "deep_scan"
    ordinary = DeepScanner(config).scan(source, reports_dir=tmp_path / "ordinary")
    reference = json.loads(Path(ordinary["results"][0]["report_path"]).read_text())
    for field in ("detections", "risk_assessment", "interesting_strings", "assurance"):
        assert report[field] == reference[field]


def test_output_limit_never_writes_report_or_quarantines(tmp_path):
    source = tmp_path / "sample"
    source.write_bytes(b"sample content")
    config = Config(tmp_path / "absent.json")
    config.set("supervised_max_output_bytes", 1)
    vault = QuarantineVault(tmp_path / "vault")
    summary = DeepScanner(config, supervised=True).scan(
        source,
        reports_dir=tmp_path / "reports",
        quarantine=vault,
        quarantine_verdicts={"INDETERMINATE", "MALICIOUS"},
        quarantine_move=True,
    )
    assert summary["analyzed_count"] == 0
    assert summary["errors"][0]["status"] == "INDETERMINATE"
    assert summary["errors"][0]["error"] == "output_limit"
    assert not list((tmp_path / "reports").iterdir())
    assert source.exists()


@pytest.mark.parametrize(
    "option,value",
    [("plugin_dirs", ["plugin"]), ("enable_authenticode_provider", True)],
)
def test_unsupported_configuration_rejected_before_creating_reports(
    tmp_path, option, value
):
    config = Config(tmp_path / "absent.json")
    config.set(option, value)
    with pytest.raises(ValueError):
        DeepScanner(config, supervised=True).scan(
            tmp_path, reports_dir=tmp_path / "reports"
        )
    assert not (tmp_path / "reports").exists()


def test_online_supervision_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="offline"):
        DeepScanner(supervised=True, offline=False).scan(tmp_path)


def test_precancelled_scan_does_not_analyze(tmp_path):
    source = tmp_path / "sample"
    source.write_bytes(b"sample")
    cancel = threading.Event()
    cancel.set()
    summary = DeepScanner(supervised=True, cancel_event=cancel).scan(
        source, reports_dir=tmp_path / "reports"
    )
    assert summary["cancelled"]
    assert summary["analyzed_count"] == 0


def test_cli_supervised_scan(tmp_path, capsys):
    source = tmp_path / "sample"
    source.write_bytes(b"ordinary sample")
    args = cli.build_parser().parse_args(
        [
            "--deep-scan",
            str(source),
            "--deep-scan-supervised",
            "--offline",
            "--deep-scan-reports",
            str(tmp_path / "reports"),
            "--stdout",
            "json",
        ]
    )
    assert cli.run_deep_scan(args, Config(tmp_path / "absent.json")) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["analyzed_count"] == 1
    assert summary["error_count"] == 0


def test_supervised_cli_returns_failure_for_partial_scan(tmp_path, monkeypatch):
    args = cli.build_parser().parse_args(
        [
            "--deep-scan",
            str(tmp_path),
            "--deep-scan-supervised",
            "--offline",
        ]
    )
    monkeypatch.setattr(
        DeepScanner,
        "scan",
        lambda *a, **k: {
            "analyzed_count": 1,
            "error_count": 1,
        },
    )
    assert cli.run_deep_scan(args, Config(tmp_path / "absent.json")) == 1


def test_supervised_flag_requires_deep_scan(monkeypatch):
    monkeypatch.setattr("sys.argv", ["titan", "--deep-scan-supervised"])
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
