import json


def test_report_includes_run_manifest():
    from titan_decoder.core.engine import TitanEngine

    engine = TitanEngine()
    report = engine.run_analysis(b"hello")

    assert "run_manifest" in report
    manifest = report["run_manifest"]
    assert "tool" in manifest
    assert "limits" in manifest
    assert "components" in manifest
    assert "effective_config" in manifest
    assert "environment" in manifest


def test_report_schema_version_matches_schema_file():
    from titan_decoder.core.engine import SCHEMA_VERSION

    schema = json.load(open("docs/report.schema.json"))
    meta_schema_version = schema["properties"]["meta"]["properties"]["schema_version"]["const"]
    manifest_schema_version = schema["properties"]["run_manifest"]["properties"]["tool"]["properties"]["schema_version"]["const"]

    assert meta_schema_version == SCHEMA_VERSION
    assert manifest_schema_version == SCHEMA_VERSION
