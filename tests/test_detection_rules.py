from titan_decoder.core.detection_rules import CorrelationRulesEngine, DetectionRule


def test_load_starter_rules():
    engine = CorrelationRulesEngine()
    assert len(engine.rules) >= 7
    rule_ids = [r.rule_id for r in engine.rules]
    assert "TITAN-001" in rule_ids
    assert "TITAN-007" in rule_ids


def test_deep_base64_detection():
    report = {
        "nodes": [
            {"depth": 0, "decoder_used": "Base64"},
            {"depth": 1, "decoder_used": "Base64"},
            {"depth": 2, "decoder_used": "Base64"},
            {"depth": 3, "decoder_used": "Base64"},
        ]
    }
    iocs = {}

    engine = CorrelationRulesEngine()
    detections = engine.evaluate_all(report, iocs)

    assert any(d["rule_id"] == "TITAN-001" for d in detections)


def test_office_macro_network_detection():
    report = {
        "nodes": [
            {"method": "ANALYZE_OLE", "content_preview": "VBA content"},
        ]
    }
    iocs = {
        "urls": ["http://malicious.com"],
        "ipv4_public": ["1.2.3.4"],
    }

    engine = CorrelationRulesEngine()
    detections = engine.evaluate_all(report, iocs)

    assert any(d["rule_id"] == "TITAN-002" for d in detections)


def test_custom_rule_addition():
    engine = CorrelationRulesEngine()
    initial_count = len(engine.rules)

    custom_rule = DetectionRule(
        rule_id="CUSTOM-001",
        name="Test Rule",
        description="A test rule",
        severity="medium",
        detect_fn=lambda report, iocs: True,
    )

    engine.add_custom_rule(custom_rule)
    assert len(engine.rules) == initial_count + 1
