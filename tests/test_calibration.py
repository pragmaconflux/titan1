import json
from pathlib import Path

import pytest

from titan_decoder import cli
from titan_decoder.config import Config
from titan_decoder.core.calibration import CalibrationRunner


CORPUS = Path(__file__).parent / "fixtures" / "calibration" / "decoder-analyzer-v1.json"


def test_calibration_supports_reviewable_base64_parts(tmp_path):
    assert (
        CalibrationRunner._case_data({"data_base64_parts": ["SGVs", "bG8="]}, tmp_path)
        == b"Hello"
    )

    with pytest.raises(ValueError, match="exactly one data representation"):
        CalibrationRunner._case_data(
            {"data_text": "Hello", "data_base64_parts": ["SGVsbG8="]}, tmp_path
        )


def test_bundled_decoder_analyzer_calibration_passes_quality_gate():
    report = CalibrationRunner().run(CORPUS)

    assert report["case_count"] == 176
    assert report["skipped_count"] == 0
    assert report["aggregate"]["precision"] == 1.0
    assert report["aggregate"]["recall"] == 1.0
    assert report["recognition_aggregate"]["precision"] == 1.0
    assert report["recognition_aggregate"]["recall"] == 1.0
    assert report["registry_coverage"]["live_builtin_count"] == 44
    assert report["registry_coverage"]["covered_count"] == 44
    assert report["registry_coverage"]["missing_positive"] == []
    assert report["registry_coverage"]["missing_negative"] == []
    assert report["case_class_coverage"]["required_by_kind"] == {
        "analyzer": ["malformed", "truncated"],
        "decoder": ["malformed", "truncated"],
    }
    assert report["case_class_coverage"]["required_component_count"] == 44
    assert report["case_class_coverage"]["covered_count"] == 44
    assert report["case_class_coverage"]["missing"] == []
    assert report["case_class_coverage"]["per_component"]["analyzer:DEX"] == {
        "clean_negative": 1,
        "malformed": 1,
        "nested_chain": 0,
        "positive": 1,
        "size_bound": 0,
        "truncated": 1,
    }
    assert report["case_class_coverage"]["per_component"]["decoder:ASCII85"] == {
        "clean_negative": 1,
        "malformed": 1,
        "nested_chain": 0,
        "positive": 1,
        "size_bound": 0,
        "truncated": 1,
    }
    assert report["quality_gate"]["passed"] is True
    assert report["components"]["decoder:ASCII85"]["true_positive"] == 1
    assert report["components"]["analyzer:OfficeOOXML"]["true_negative"] == 2


def test_calibration_detects_output_regression(tmp_path):
    corpus = tmp_path / "regression.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "wrong-output",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_text": "<~87cURD_*#1Blmd$+T~>",
                        "expected_match": True,
                        "expected_output_sha256": "0" * 64,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["aggregate"]["false_negative"] == 1
    assert report["quality_gate"]["passed"] is False


def test_registry_parity_reports_missing_live_component_slices(tmp_path):
    corpus = tmp_path / "partial.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "require_registry_parity": True,
                "cases": [
                    {
                        "id": "ascii85-positive-only",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_text": "<~87cURD_*#1Blmd$+T~>",
                        "expected_match": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["quality_gate"]["passed"] is False
    assert "decoder:Base64" in report["registry_coverage"]["missing_positive"]
    assert "decoder:ASCII85" in report["registry_coverage"]["missing_negative"]


def test_registry_parity_exemptions_cannot_bypass_live_coverage(tmp_path):
    corpus = tmp_path / "exempt.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "require_registry_parity": True,
                "exempt_components": ["analyzer:PE"],
                "cases": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="every live built-in must be covered"):
        CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)


def test_case_class_gate_reports_missing_live_analyzer_slices(tmp_path):
    corpus = tmp_path / "partial-adversarial.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "required_case_classes": {"analyzer": ["malformed", "truncated"]},
                "cases": [
                    {
                        "id": "email-malformed",
                        "kind": "analyzer",
                        "component": "Email",
                        "case_class": "malformed",
                        "data_text": "From: a@example.test\r\n\r\nbody",
                        "expected_match": True,
                        "expected_artifacts": ["email_summary.json"],
                    },
                    {
                        "id": "email-truncated",
                        "kind": "analyzer",
                        "component": "Email",
                        "case_class": "truncated",
                        "data_text": "From: a@example.test",
                        "expected_match": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    coverage = report["case_class_coverage"]
    assert coverage["required_component_count"] == 18
    assert coverage["covered_count"] == 1
    assert coverage["covered_components"] == ["analyzer:Email"]
    assert {
        (item["component"], item["case_class"]) for item in coverage["missing"]
    } >= {
        ("analyzer:DEX", "malformed"),
        ("analyzer:DEX", "truncated"),
    }
    assert report["quality_gate"]["passed"] is False


def test_invalid_case_class_cannot_earn_coverage(tmp_path):
    corpus = tmp_path / "invalid-class.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "invalid-class",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "case_class": "damaged",
                        "data_text": "ordinary prose is not ascii85",
                        "expected_match": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["case_count"] == 0
    assert report["quality_gate"]["passed"] is False
    assert any(
        "invalid-class: case_class must be one of" in str(failure)
        for failure in report["quality_gate"]["failures"]
    )


def test_invalid_required_case_classes_contract_is_rejected(tmp_path):
    corpus = tmp_path / "invalid-required-classes.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "required_case_classes": {"analyzer": ["damaged"]},
                "cases": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="required_case_classes.analyzer"):
        CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)


def test_derived_adversarial_case_mutations_are_deterministic(tmp_path):
    corpus = tmp_path / "derived.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "ascii85-source",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_text": "<~87cURD_*#1Blmd$+T~>",
                        "expected_match": True,
                    },
                    {
                        "id": "ascii85-derived-malformed",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "case_class": "malformed",
                        "derive_from": "ascii85-source",
                        "mutation": "flip-middle-byte",
                        "expected_match": False,
                    },
                    {
                        "id": "ascii85-derived-truncated",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "case_class": "truncated",
                        "derive_from": "ascii85-source",
                        "mutation": "truncate-half",
                        "expected_match": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["quality_gate"]["passed"] is True
    assert report["case_count"] == 3
    assert (
        report["case_class_coverage"]["per_component"]["decoder:ASCII85"]["malformed"]
        == 1
    )
    assert (
        report["case_class_coverage"]["per_component"]["decoder:ASCII85"]["truncated"]
        == 1
    )
    assert not any(
        "ascii85-derived" in str(failure)
        for failure in report["quality_gate"]["failures"]
    )


def test_invalid_derived_case_reference_fails_closed(tmp_path):
    corpus = tmp_path / "derived-invalid.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "derived-invalid",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "derive_from": "missing-source",
                        "mutation": "truncate-half",
                        "expected_match": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["quality_gate"]["passed"] is False
    assert any(
        "derived case references unknown case" in str(failure)
        for failure in report["quality_gate"]["failures"]
    )


def test_cyclic_derived_case_references_fail_closed(tmp_path):
    corpus = tmp_path / "derived-cycle.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "derived-cycle-a",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "derive_from": "derived-cycle-b",
                        "mutation": "truncate-half",
                        "expected_match": False,
                    },
                    {
                        "id": "derived-cycle-b",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "derive_from": "derived-cycle-a",
                        "mutation": "flip-middle-byte",
                        "expected_match": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["quality_gate"]["passed"] is False
    assert any(
        "derived case references contain a cycle" in str(failure)
        for failure in report["quality_gate"]["failures"]
    )


def test_optional_dependency_skips_extraction_but_measures_recognition(tmp_path):
    corpus = tmp_path / "optional.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "optional-ascii85",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_text": "<~87cURD_*#1Blmd$+T~>",
                        "expected_recognition": True,
                        "expected_match": True,
                        "required_modules": ["titan_test_module_that_does_not_exist"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["recognition_aggregate"]["true_positive"] == 1
    assert report["components"] == {}
    assert report["dependency_skips"] == [
        {
            "id": "optional-ascii85",
            "component": "decoder:ASCII85",
            "missing_modules": ["titan_test_module_that_does_not_exist"],
        }
    ]
    assert report["quality_gate"]["passed"] is True


def test_invalid_negative_case_cannot_earn_quality_credit(tmp_path):
    corpus = tmp_path / "invalid-negative.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "invalid-negative",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_base64": "not-valid-base64!",
                        "expected_match": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["quality_gate"]["passed"] is False
    assert any(
        "invalid-negative: evaluation error" in str(failure)
        for failure in report["quality_gate"]["failures"]
    )


def test_unknown_component_cannot_be_silently_skipped(tmp_path):
    corpus = tmp_path / "unknown-component.json"
    corpus.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "cases": [
                    {
                        "id": "known",
                        "kind": "decoder",
                        "component": "ASCII85",
                        "data_text": "ordinary prose is not ascii85",
                        "expected_match": False,
                    },
                    {
                        "id": "unknown",
                        "kind": "decoder",
                        "component": "NotARealDecoder",
                        "data_text": "payload",
                        "expected_match": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    report = CalibrationRunner(Config(tmp_path / "missing.json")).run(corpus)

    assert report["skipped_count"] == 1
    assert report["quality_gate"]["passed"] is False
    assert any(
        "unknown or unavailable component decoder:NotARealDecoder" in str(failure)
        for failure in report["quality_gate"]["failures"]
    )


def test_cli_calibration_writes_report(tmp_path, capsys):
    output = tmp_path / "calibration-report.json"
    args = cli.build_parser().parse_args(
        ["--calibrate", str(CORPUS), "--calibration-out", str(output)]
    )

    assert cli.handle_info_commands(args, Config(tmp_path / "missing.json")) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["quality_gate"]["passed"]
    assert json.loads(capsys.readouterr().out)["case_count"] == 176
