from titan_decoder.core.timeline import build_timeline


def test_timeline_matches_nodes():
    report = {
        "nodes": [
            {"id": 0, "parent": None, "depth": 0, "method": "ANALYZE", "decoder_used": None, "content_type": "Binary", "decoded_length": 4, "sha256": "abc", "decode_score": 0.1, "pruned": False, "content_preview": "AAAA"},
            {"id": 1, "parent": 0, "depth": 1, "method": "Base64", "decoder_used": "Base64", "content_type": "Text", "decoded_length": 5, "sha256": "def", "decode_score": 0.8, "pruned": False, "content_preview": "hello"},
        ]
    }

    timeline = build_timeline(report)

    assert len(timeline) == 2
    assert timeline[0]["order"] == 0
    assert timeline[1]["parent"] == 0
    assert timeline[1]["decoder"] == "Base64"
    assert "preview" in timeline[0]
