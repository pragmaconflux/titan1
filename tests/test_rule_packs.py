import json


def test_rule_pack_content_regex(tmp_path):
    pack = {
        "schema_version": 1,
        "pack": {"name": "Test Pack", "version": "0.1.0"},
        "rules": [
            {
                "id": "TP-001",
                "name": "Find powershell",
                "description": "Detect powershell strings",
                "severity": "medium",
                "type": "content_regex",
                "pattern": "powershell",
                "flags": ["IGNORECASE"],
            }
        ],
    }
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(pack))

    from titan_decoder.core.detection_rules import CorrelationRulesEngine

    engine = CorrelationRulesEngine([path])
    report = {"nodes": [{"content_preview": "Running PowerShell -enc ..."}]}
    iocs = {}
    detections = engine.evaluate_all(report, iocs)

    assert any(d["rule_id"] == "TP-001" for d in detections)
    det = next(d for d in detections if d["rule_id"] == "TP-001")
    assert det["source"]["type"] == "pack"
    assert det["source"]["pack"] == "Test Pack"


def test_rule_pack_ioc_present(tmp_path):
    pack = {
        "schema_version": 1,
        "pack": {"name": "Test Pack", "version": "0.1.0"},
        "rules": [
            {
                "id": "TP-002",
                "name": "Has infra",
                "description": "URLs and public IPs",
                "severity": "high",
                "type": "ioc_present",
                "ioc_types": ["urls", "ipv4_public"],
                "min_each": 1,
            }
        ],
    }
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(pack))

    from titan_decoder.core.detection_rules import CorrelationRulesEngine

    engine = CorrelationRulesEngine([path])
    report = {"nodes": []}
    iocs = {"urls": ["http://example.com"], "ipv4_public": ["1.2.3.4"]}
    detections = engine.evaluate_all(report, iocs)
    assert any(d["rule_id"] == "TP-002" for d in detections)
