"""Host-embedded corpus: every decoder, exercised through a carrier file.

Every fixture in the calibration corpus is a *whole-buffer* case -- the
artifact under test **is** the encoded payload. Real samples carry the payload
inside a host, and Titan's decoders are whole-buffer transforms, so a corpus
made only of whole-buffer cases cannot observe the engine's largest blind
spot. It reported 1.0 precision and recall while a JS dropper carrying
base64(gzip(powershell -EncodedCommand ...)) produced no IOCs at all.

This module derives a host-embedded variant of every decoder positive case in
the live corpus and runs it through the **engine**, not through the decoder in
isolation, so decoder selection and the carving pass are both in scope.

The point is to find misses, so the expected-miss list below is part of the
contract in both directions. A case that starts missing fails the test as a
regression; a case that stops missing also fails it, forcing the list and its
documented reasons to stay truthful rather than accumulating stale excuses.
"""

import base64
import json
from pathlib import Path

import pytest

from titan_decoder.config import Config
from titan_decoder.core.engine import TitanEngine

CORPUS = Path(__file__).parent / "fixtures" / "calibration" / "decoder-analyzer-v1.json"

# Case id -> why the payload is not recovered once embedded in a host. Each
# entry is a real gap, not an exemption: shrink this list, do not grow it.
KNOWN_MISSES = {
    "base58-positive": (
        "15-byte payload encodes to 20 base64 characters, below the carver's "
        "24-character minimum run; shortening it would cost more precision "
        "than the recall is worth"
    ),
    "base91-positive": (
        "15-byte payload, same sub-minimum run length as base58-positive"
    ),
    "brotli-positive": (
        "Brotli streams are headerless and carry no signature, so the carving "
        "gate cannot recognize the decoded region without trial-decompressing "
        "with the optional brotli module"
    ),
}


def _case_payload(case: dict) -> bytes | None:
    if "data_text" in case:
        return str(case["data_text"]).encode()
    if "data_base64" in case:
        return base64.b64decode(str(case["data_base64"]))
    return None  # derived case (mutation of another); not a standalone payload


def _decoder_positives() -> list[tuple[str, bytes, str]]:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    cases = []
    for case in corpus["cases"]:
        if case.get("kind") != "decoder" or case.get("expected_match") is not True:
            continue
        expected = case.get("expected_output_sha256")
        if not expected:
            continue
        payload = _case_payload(case)
        if payload is None:
            continue
        cases.append((str(case["id"]), payload, str(expected)))
    return sorted(cases)


def _embed_in_host(payload: bytes) -> bytes:
    """Wrap a payload the way a real dropper carries it: base64 in a variable."""
    return (
        "var cfg = 1;\nvar blob = '"
        + base64.b64encode(payload).decode()
        + "';\nrun(blob);\n"
    ).encode()


def _recovers(payload: bytes, expected_sha256: str) -> bool:
    config = Config()
    config.set("max_recursion_depth", 8)
    report = TitanEngine(config).run_analysis(_embed_in_host(payload))
    return any(node["sha256"] == expected_sha256 for node in report["nodes"])


def test_corpus_supplies_host_embedded_cases():
    cases = _decoder_positives()
    assert len(cases) >= 20, "decoder positives should cover most of the registry"


@pytest.mark.parametrize("case_id,payload,expected", _decoder_positives())
def test_decoder_payload_survives_being_embedded_in_a_host(case_id, payload, expected):
    recovered = _recovers(payload, expected)
    if case_id in KNOWN_MISSES:
        assert not recovered, (
            f"{case_id} now recovers when embedded in a host. This is good news: "
            f"remove it from KNOWN_MISSES. Recorded reason was: "
            f"{KNOWN_MISSES[case_id]}"
        )
    else:
        assert recovered, (
            f"{case_id} decodes standalone but is lost when embedded in a host. "
            "Either fix the gap or record it in KNOWN_MISSES with a reason."
        )


def test_known_miss_list_has_no_stale_entries():
    known_ids = {case_id for case_id, _, _ in _decoder_positives()}
    stale = set(KNOWN_MISSES) - known_ids
    assert not stale, f"KNOWN_MISSES references cases that no longer exist: {stale}"


def test_recovery_rate_does_not_regress():
    # A single number the depth program can track over time. Raise the floor
    # when the rate improves; never lower it to make a change pass.
    cases = _decoder_positives()
    recovered = sum(1 for _, payload, expected in cases if _recovers(payload, expected))
    assert recovered == len(cases) - len(KNOWN_MISSES)
    assert recovered / len(cases) >= 0.88
