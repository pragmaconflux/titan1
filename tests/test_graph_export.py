import json


def test_graph_export_json_includes_metadata_counts_and_depth():
    from titan_decoder.core.graph_export import GraphExporter

    nodes = [
        {"id": 0, "parent": None, "depth": 0, "method": "ANALYZE"},
        {"id": 1, "parent": 0, "depth": 1, "method": "ANALYZE"},
        {"id": 2, "parent": 1, "depth": 2, "method": "ANALYZE_ZIP"},
    ]

    data = json.loads(GraphExporter(nodes).to_json(include_metadata=True))
    assert "metadata" in data
    assert data["metadata"]["total_nodes"] == 3
    assert data["metadata"]["max_depth"] == 2
    assert "node_types" in data["metadata"]
    assert data["metadata"]["node_types"]["ANALYZE"] == 2
    assert data["metadata"]["node_types"]["ANALYZE_ZIP"] == 1


def test_graph_export_edges_mark_pruned_children():
    from titan_decoder.core.graph_export import GraphExporter

    nodes = [
        {"id": 0, "parent": None, "depth": 0, "method": "ANALYZE"},
        {"id": 1, "parent": 0, "depth": 1, "method": "ANALYZE", "pruned": True},
    ]

    data = json.loads(GraphExporter(nodes).to_json(include_metadata=False))
    assert any(e.get("type") == "pruned" for e in data.get("edges") or [])


def test_graph_export_mermaid_uses_labeled_edge_syntax():
    from titan_decoder.core.graph_export import GraphExporter

    nodes = [
        {"id": 0, "parent": None, "depth": 0, "method": "ANALYZE"},
        {"id": 1, "parent": 0, "depth": 1, "method": "ANALYZE", "decoder_used": "zip|inflate"},
    ]

    mermaid = GraphExporter(nodes).to_mermaid()
    # Mermaid labeled edges should look like: 0 -->|label| 1
    assert "-->|" in mermaid
    # Ensure we don't emit the old edge-label bracket syntax
    assert "[\"" not in mermaid
