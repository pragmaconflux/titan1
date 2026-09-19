"""Amplifying components must prove their output cap holds.

`size_bound` is a declared calibration case class that read zero for every
component. Unlike `nested_chain` -- which cannot be expressed against a
component in isolation at all -- this one is genuinely expressible, so it was
a real gap rather than a category error.

It is only meaningful where a component can amplify, though. ROT13 and Base64
cannot produce more output than their input warrants, so demanding the class
of all 44 components would manufacture fixtures that measure nothing. The
requirement is therefore derived from the live registry: a component that
exposes an output cap has to carry a case proving it.

Exercising a 50 MB cap honestly would mean committing real decompression
bombs and allocating 50 MB per case in CI, so a case may instead shrink the
cap for its own duration and trip it with a few hundred bytes.
"""

import base64
import copy
import gzip
import json
from pathlib import Path

import pytest

from titan_decoder.config import Config
from titan_decoder.core.calibration import (
    _OUTPUT_CAP_ATTRIBUTES,
    CalibrationRunner,
    output_cap_attribute,
)
from titan_decoder.core.engine import TitanEngine

CORPUS = Path(__file__).parent / "fixtures" / "calibration" / "decoder-analyzer-v1.json"


def _corpus() -> dict:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def _run(corpus: dict, tmp_path: Path) -> dict:
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(corpus), encoding="utf-8")
    return CalibrationRunner(Config()).run(path)


def _amplifying_decoders() -> list[str]:
    engine = TitanEngine(Config())
    return sorted(
        decoder.name
        for decoder in engine.decoders
        if any(hasattr(decoder, attr) for attr in _OUTPUT_CAP_ATTRIBUTES)
    )


def _amplifying_analyzers() -> list[str]:
    engine = TitanEngine(Config())
    return sorted(
        analyzer.name
        for analyzer in engine.analyzers
        if output_cap_attribute("analyzer", analyzer) is not None
    )


def test_every_amplifying_analyzer_has_a_size_bound_case():
    # Analyzers name the same idea differently (max_total / max_total_size),
    # so they were invisible to a decoder-shaped cap lookup.
    coverage = CalibrationRunner(Config()).run(CORPUS)["case_class_coverage"]
    per_component = coverage["per_component"]
    for name in _amplifying_analyzers():
        assert per_component[f"analyzer:{name}"]["size_bound"] >= 1, name


def test_analyzer_summaries_count_against_the_declared_cap():
    # The summary used to be spliced past the collector, so an analyzer's real
    # ceiling was max_total + max_item rather than the max_total it declares.
    report = CalibrationRunner(Config()).run(CORPUS)
    analyzer_cases = [
        case
        for case in report["cases"]
        if case["case_class"] == "size_bound" and case["kind"] == "analyzer"
    ]
    assert analyzer_cases
    for case in analyzer_cases:
        emitted = case.get("output_bytes")
        if emitted is None:
            continue
        assert emitted <= 256, f"{case['id']} emitted {emitted}"


def test_gate_fails_when_an_analyzer_exceeds_its_bound(tmp_path):
    # The regression this whole slice exists for: six analyzers overshot their
    # declared max_total because summaries bypassed the collector.
    corpus = _corpus()
    for case in corpus["cases"]:
        if case["id"] == "email-size-bound":
            case["expected_max_output_bytes"] = 16
    report = _run(corpus, tmp_path)
    assert not report["quality_gate"]["passed"]
    assert any(
        "email-size-bound" in failure for failure in report["quality_gate"]["failures"]
    ), report["quality_gate"]["failures"]


def test_every_amplifying_decoder_has_a_size_bound_case():
    coverage = CalibrationRunner(Config()).run(CORPUS)["case_class_coverage"]
    per_component = coverage["per_component"]
    for name in _amplifying_decoders():
        assert per_component[f"decoder:{name}"]["size_bound"] >= 1, name


def test_one_to_one_decoders_are_not_required_to_have_one():
    # Requiring the class where it cannot be measured is the category error
    # that keeps nested_chain permanently zero; do not repeat it here.
    amplifying = set(_amplifying_decoders())
    engine = TitanEngine(Config())
    transforms = [d.name for d in engine.decoders if d.name not in amplifying]
    assert "ROT13" in transforms and "Base64" in transforms

    report = CalibrationRunner(Config()).run(CORPUS)
    assert report["quality_gate"]["passed"], report["quality_gate"]["failures"]


def test_gate_fails_when_an_amplifying_decoder_loses_its_case(tmp_path):
    corpus = _corpus()
    corpus["cases"] = [c for c in corpus["cases"] if c["id"] != "gzip-size-bound"]
    report = _run(corpus, tmp_path)
    assert not report["quality_gate"]["passed"]
    assert any(
        "decoder:Gzip" in failure and "size_bound" in failure
        for failure in report["quality_gate"]["failures"]
    ), report["quality_gate"]["failures"]


def test_bombs_are_refused_whatever_shape_the_refusal_takes(tmp_path):
    # Some decoders decline at recognition, some fail the decode, and some
    # truncate to the cap. All three are correct; none may exceed the bound.
    report = CalibrationRunner(Config()).run(CORPUS)
    cases = {c["id"]: c for c in report["cases"] if c["case_class"] == "size_bound"}
    assert len(cases) == len(_amplifying_decoders()) + len(_amplifying_analyzers())
    for case_id, case in cases.items():
        within = case.get("output_within_bound")
        assert within in (True, None), f"{case_id} exceeded its bound"


def test_override_is_restored_after_the_case():
    # The registry is shared across cases, so a leaked override would quietly
    # change every later case's bounds.
    engine = TitanEngine(Config())
    decoder = next(d for d in engine.decoders if d.name == "Gzip")
    before = decoder.max_output_size
    case = {"component_overrides": {"max_output_size": 4096}}
    with CalibrationRunner._component_overrides(decoder, case):
        assert decoder.max_output_size == 4096
    assert decoder.max_output_size == before


def test_override_is_restored_even_when_the_case_raises():
    engine = TitanEngine(Config())
    decoder = next(d for d in engine.decoders if d.name == "Gzip")
    before = decoder.max_output_size
    case = {"component_overrides": {"max_output_size": 4096}}
    with pytest.raises(RuntimeError):
        with CalibrationRunner._component_overrides(decoder, case):
            raise RuntimeError("boom")
    assert decoder.max_output_size == before


@pytest.mark.parametrize(
    "overrides",
    [
        {"not_a_real_attribute": 4096},
        {"max_output_size": 0},
        {"max_output_size": -1},
        {"max_output_size": "4096"},
        {"max_output_size": True},
    ],
)
def test_invalid_overrides_are_rejected(overrides):
    # A case must not be able to invent configuration production never reads,
    # or disable a bound by setting it to zero.
    engine = TitanEngine(Config())
    decoder = next(d for d in engine.decoders if d.name == "Gzip")
    with pytest.raises(ValueError):
        with CalibrationRunner._component_overrides(
            decoder, {"component_overrides": overrides}
        ):
            pass


def test_output_exceeding_its_declared_bound_fails_the_case(tmp_path):
    # The bound assertion has to be able to fail, or it is decoration: give a
    # passing case a bound smaller than the output it really produces.
    corpus = _corpus()
    payload = base64.b64encode(
        gzip.compress(b"bounded payload " * 64, mtime=0)
    ).decode()
    corpus["cases"] = copy.deepcopy(corpus["cases"]) + [
        {
            "id": "gzip-bound-too-small",
            "kind": "decoder",
            "component": "Gzip",
            "case_class": "size_bound",
            "data_base64": payload,
            "expected_recognition": True,
            "expected_match": True,
            "expected_max_output_bytes": 8,
        }
    ]
    report = _run(corpus, tmp_path)
    case = next(c for c in report["cases"] if c["id"] == "gzip-bound-too-small")
    assert case["output_within_bound"] is False
    assert case["outcome"] == "false_negative"
    assert not report["quality_gate"]["passed"]
