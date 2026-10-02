"""Regressions found by fuzzing the engine end to end.

Each test pins one finding from the complexity, mutation, and CLI-surface
campaigns, so the bug cannot come back quietly. Timing bounds are generous:
they separate linear from quadratic by orders of magnitude, not by
milliseconds, so they do not flake on a slow runner.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from titan_decoder.analyst.engine import AnalystEngine
from titan_decoder.analyst.validation import validate_answer
from titan_decoder.config import Config
from titan_decoder.core.engine import TitanEngine
from titan_decoder.decoders.advanced import Base58Decoder
from titan_decoder.utils.helpers import extract_iocs

ROOT = Path(__file__).parents[1]


def _elapsed(fn, *args):
    start = time.perf_counter()
    fn(*args)
    return time.perf_counter() - start


# --------------------------------------------------------------- complexity
@pytest.mark.parametrize(
    "unit", ["a.", "a-a.", "a@a.", "a.a@", "1.", "%41a."], ids=repr
)
def test_ioc_extraction_is_linear_on_label_runs(unit):
    # Unbounded label repetition made domain/email matching quadratic once IOC
    # extraction scanned whole artifacts: "a." * 524288 ran for minutes.
    data = unit * (256 * 1024 // len(unit))
    assert _elapsed(extract_iocs, data) < 5.0


def test_base58_rejects_oversized_candidates_quickly():
    # Base58 decoding is big-integer arithmetic, quadratic in length; a 4MB
    # base64-shaped run would have taken over an hour.
    data = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" * 4096
    decoder = Base58Decoder()

    def run():
        if decoder.can_decode(data):
            decoder.decode(data)

    assert _elapsed(run) < 2.0
    assert not decoder.can_decode(data)


def test_base58_still_decodes_short_identifiers():
    decoder = Base58Decoder()
    encoded = b"StV1DL6CwTryKyV"  # "hello world"
    assert decoder.can_decode(encoded)
    assert decoder.decode(encoded) == (b"hello world", True)


# ----------------------------------------------------------------- IOC shape
def test_domain_longer_than_rfc_limit_is_not_an_indicator():
    fused = "entity.example" * 40 + ".com"
    assert len(fused) > 253
    assert fused.lower() not in extract_iocs(f"see {fused} now")["domains"]


def test_domain_at_rfc_limit_is_kept():
    labels = ["a" * 61] * 4  # 4 * 62 = 248 chars incl. dots, + "com"
    name = ".".join(labels) + ".com"
    assert len(name) <= 253
    assert name in extract_iocs(f"host {name} here")["domains"]


def test_email_with_overlong_host_is_dropped():
    host = ".".join(["b" * 60] * 5) + ".com"
    assert f"x@{host}" not in extract_iocs(f"mail x@{host} now")["emails"]


@pytest.mark.parametrize("control", ["\x00", "\x01", "\x1b", "\x7f", "\x85"])
def test_url_stops_at_control_characters(control):
    urls = extract_iocs(f"get http://example.com/a{control}garbage")["urls"]
    assert urls == ["http://example.com/a"]


# ------------------------------------------------------------------ analyst
def test_deterministic_answer_with_unicode_indicator_validates():
    # The validator compared raw claim tokens to a JSON-escaped corpus, so an
    # indicator containing any non-ASCII character could never be found in
    # its own evidence and the engine's own answer failed validation.
    payload = "beacon to http://example.com/päth̶x?q=1 every hour\n"
    report = TitanEngine(Config()).run_analysis(payload.encode("utf-8"))
    assert any("ä" in url for url in report["iocs"]["urls"])
    analyst = AnalystEngine([report])
    for question in ("What indicators were found?", "What is this file?"):
        answer = analyst.ask(question).answer
        result = validate_answer(answer, analyst.index)
        assert result.ok, (question, answer, result)


# ---------------------------------------------------------------------- CLI
def _cli(*args, tmp_path):
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    return subprocess.run(
        [sys.executable, "-m", "titan_decoder.cli", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "sample.txt"
    path.write_bytes(b"powershell -enc SQBFAFgA http://example.com/payload\n")
    return path


def test_perf_profile_keeps_json_stdout_parseable(sample, tmp_path):
    # The profile table was printed to stdout, so --stdout json was not JSON.
    profile = tmp_path / "profile.json"
    result = _cli(
        "--file", str(sample), "--offline", "--quiet", "--stdout", "json",
        "--perf-profile", "--profile-out", str(profile), tmp_path=tmp_path,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    json.loads(result.stdout)
    assert "PERFORMANCE PROFILE RESULTS" in result.stderr

    data = json.loads(profile.read_text())
    # The table parser read per-call tottime instead of cumtime, so every
    # function reported ~0s; and the call count was distinct functions.
    assert max(data["top_functions"].values()) > 0
    assert data["function_calls"] > len(data["top_functions"])
    assert any("run_analysis" in name for name in data["top_functions"])


def test_quiet_suppresses_info_logs(sample, tmp_path):
    result = _cli(
        "--file", str(sample), "--offline", "--quiet", "--stdout", "none",
        tmp_path=tmp_path,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert "[INFO]" not in result.stderr


def test_fail_on_risk_level_is_case_insensitive(sample, tmp_path):
    result = _cli(
        "--file", str(sample), "--offline", "--quiet", "--stdout", "none",
        "--fail-on-risk-level", "critical", tmp_path=tmp_path,
    )  # fmt: skip
    assert "invalid choice" not in result.stderr
    assert result.returncode in (0, 1, 2, 3, 4)


# ----------------------------------------------------------- hostile probes
def _zip_with_version_needed(
    version: int, names=("[Content_Types].xml", "word/document.xml")
) -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name in names:
            archive.writestr(name, b"<x/>")
    data = bytearray(buf.getvalue())
    # Patch "version needed to extract" in every central directory record.
    offset = data.find(b"PK\x01\x02")
    while offset != -1:
        data[offset + 6 : offset + 8] = version.to_bytes(2, "little")
        offset = data.find(b"PK\x01\x02", offset + 4)
    return bytes(data)


def test_unsupported_zip_version_does_not_abort_analysis():
    # zipfile raises NotImplementedError for an unknown "version needed";
    # the OOXML probe caught only BadZipFile, and the engine called probes
    # unguarded, so a one-bit flip in a ZIP failed the entire run.
    report = TitanEngine(Config()).run_analysis(_zip_with_version_needed(84))
    assert report["node_count"] >= 1


def test_raising_probe_is_contained():
    import struct

    class Exploding:
        name = "Exploding"

        def can_decode(self, data):
            raise struct.error("boom")

        def can_analyze(self, data):
            raise struct.error("boom")

    config = Config()
    config.set("include_decision_trace", True)
    engine = TitanEngine(config)
    engine.decoders.insert(0, Exploding())
    engine.analyzers.insert(0, Exploding())
    report = engine.run_analysis(b"SGVsbG8gd29ybGQ=")
    assert report["node_count"] >= 2  # Base64 still decoded
    failures = [
        step
        for step in report.get("decision_trace", [])
        if step.get("name") == "Exploding"
    ]
    assert failures and all(step["success"] is False for step in failures)
