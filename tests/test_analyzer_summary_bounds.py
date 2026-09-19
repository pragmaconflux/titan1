"""Analyzer summaries must stay parseable JSON when they hit their cap.

Five structured analyzers bounded their summary with ``encoded[: max_item]``
-- a byte slice of serialized JSON. When it triggered, the artifact ended
mid-token and was unparseable, silently, because nothing downstream
re-validates analyzer metadata before writing it into the report, the graph,
or the AI analyst's evidence ledger.

Reaching the cap does not take a crafted bomb: summary size grows with the
input, so an ordinary large document gets there. An email with sixty
attachment filenames produced an ``email_summary.json`` ending in the middle
of a string.
"""

import json
from pathlib import Path

import pytest

from titan_decoder.config import Config
from titan_decoder.core.analyzers.structured import _bounded_summary
from titan_decoder.core.calibration import CalibrationRunner
from titan_decoder.core.engine import TitanEngine

CORPUS = Path(__file__).parent / "fixtures" / "calibration" / "decoder-analyzer-v1.json"
SUMMARY_ANALYZERS = ("Email", "OfficeOOXML", "RTF", "MSI", "OneNote")


def _analyzer(name: str):
    return next(a for a in TitanEngine(Config()).analyzers if a.name == name)


def _positive_fixture(component: str) -> bytes:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    definitions = {c["id"]: c for c in corpus["cases"]}
    case = next(
        c
        for c in corpus["cases"]
        if c.get("kind") == "analyzer"
        and c.get("component") == component
        and c.get("expected_match") is True
    )
    return CalibrationRunner._case_data(
        case, CORPUS.parent, case_definitions=definitions
    )


def _crowded_email(parts: int = 60, name_length: int = 64) -> bytes:
    chunks = [
        b"From: a@b.test\r\nTo: c@d.test\r\nSubject: x\r\n",
        b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n',
    ]
    for index in range(parts):
        filename = ("A" * name_length + f"{index}.txt").encode()
        chunks.append(b"--B\r\nContent-Type: text/plain\r\n")
        chunks.append(
            b'Content-Disposition: attachment; filename="'
            + filename
            + b'"\r\n\r\nx\r\n'
        )
    chunks.append(b"--B--\r\n")
    return b"".join(chunks)


@pytest.mark.parametrize("limit", [4096, 2048, 512, 200])
def test_email_summary_stays_parseable_at_its_cap(limit):
    analyzer = _analyzer("Email")
    data = _crowded_email()
    original = analyzer.max_item
    try:
        analyzer.max_item = limit
        artifacts = analyzer.analyze(data)
    finally:
        analyzer.max_item = original
    summary = next(v for n, v in artifacts if n == "email_summary.json")
    assert len(summary) <= limit
    json.loads(summary)  # must not raise


@pytest.mark.parametrize("component", SUMMARY_ANALYZERS)
@pytest.mark.parametrize("limit", [4096, 512, 200])
def test_every_summary_analyzer_emits_valid_json_under_pressure(component, limit):
    analyzer = _analyzer(component)
    data = _positive_fixture(component)
    original = analyzer.max_item
    try:
        analyzer.max_item = limit
        artifacts = analyzer.analyze(data)
    finally:
        analyzer.max_item = original
    for name, content in artifacts:
        if not name.endswith(".json"):
            continue
        assert len(content) <= limit, f"{component}/{name} exceeded its cap"
        json.loads(content)


def test_truncated_summaries_say_so():
    summary = {"analyzer": "email", "parts": [{"filename": "x" * 200}] * 40}
    encoded = _bounded_summary(summary, 1024)
    assert encoded is not None
    parsed = json.loads(encoded)
    assert parsed["truncated"] is True
    assert len(parsed["parts"]) < 40


def test_summary_within_its_budget_is_untouched():
    summary = {"analyzer": "email", "parts": [1, 2, 3]}
    parsed = json.loads(_bounded_summary(summary, 1 << 20))
    assert parsed == summary
    assert "truncated" not in parsed


def test_summary_is_omitted_rather_than_emitted_broken():
    # Better no metadata artifact than an unparseable one.
    summary = {"analyzer": "email", "parts": [{"filename": "x" * 200}] * 40}
    assert _bounded_summary(summary, 8) is None


def test_trimming_converges_on_a_large_summary():
    # Halving rather than popping keeps this from re-serializing thousands of
    # times; a naive loop would make a big summary pathologically slow.
    summary = {"analyzer": "msi", "table_names": [f"table_{i}" for i in range(20000)]}
    encoded = _bounded_summary(summary, 2048)
    assert encoded is not None and len(encoded) <= 2048
    json.loads(encoded)


def test_no_analyzer_still_slices_serialized_json():
    # Guard the fix itself: the byte-slice idiom must not come back.
    source = (
        Path(__file__).parents[1]
        / "titan_decoder"
        / "core"
        / "analyzers"
        / "structured.py"
    ).read_text(encoding="utf-8")
    assert "encoded[: self.max_item]" not in source
    assert "encoded_summary[: self.max_item]" not in source
