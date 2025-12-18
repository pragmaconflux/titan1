import pytest
import base64
import gzip
from titan_decoder.core.engine import TitanEngine
from titan_decoder.core.scoring import ScoringEngine


def test_base64_decoding():
    """Test basic Base64 decoding."""
    original = b"Hello, World!"
    encoded = base64.b64encode(original)

    engine = TitanEngine()
    report = engine.run_analysis(encoded)

    assert report["node_count"] >= 2  # Original + decoded
    assert any("Hello, World!" in node["content_preview"] for node in report["nodes"])


def test_gzip_decoding():
    """Test Gzip decompression."""
    original = b"This is a test string for gzip compression."
    compressed = gzip.compress(original)

    engine = TitanEngine()
    report = engine.run_analysis(compressed)

    assert report["node_count"] >= 2
    assert any("test string" in node["content_preview"] for node in report["nodes"])


def test_ioc_extraction():
    """Test IOC extraction from decoded content."""
    text = "Visit http://malicious.com and contact admin@evil.org. IP: 192.168.1.1"
    data = base64.b64encode(text.encode())

    engine = TitanEngine()
    report = engine.run_analysis(data)

    iocs = report["iocs"]
    assert "http://malicious.com" in iocs["urls"]
    assert "admin@evil.org" in iocs["emails"]
    assert "192.168.1.1" in iocs["ipv4"]


def test_max_depth():
    """Test recursion depth limit."""
    # Create deeply nested base64
    data = b"SGVsbG8="  # "Hello" in base64
    for _ in range(10):  # Nest it deeply
        data = base64.b64encode(data)

    engine = TitanEngine()
    engine.MAX_RECURSION_DEPTH = 3
    report = engine.run_analysis(data)

    # Should not exceed max depth
    max_depth = max(node["depth"] for node in report["nodes"])
    assert max_depth <= 3


def test_scoring_system():
    """Test the scoring system functionality."""
    # Test entropy reduction scoring
    high_entropy = b'\x00\x01\x02\x03\x04\x05\x06\x07'  # High entropy
    low_entropy = b'Hello World Hello World'  # Low entropy, structured

    score = ScoringEngine.calculate_decode_score(high_entropy, low_entropy, "Base64", 0)
    assert score > 0.0  # Should get a positive score for entropy reduction

    # Test printable ratio gain
    binary_data = b'\x00\x01\x02\x03\x04\x05'
    text_data = b'Hello World!'

    score = ScoringEngine.calculate_decode_score(binary_data, text_data, "Base64", 0)
    assert score > 0.0  # Should get a positive score for more printable chars

    # Test structural emergence
    random_data = b'abcdefghijklmnop'
    json_data = b'{"key": "value"}'

    score = ScoringEngine.calculate_decode_score(random_data, json_data, "Base64", 0)
    assert score > 0.0  # Should detect JSON structure


def test_pruning_logic():
    """Test that pruning prevents excessive analysis."""
    from titan_decoder.core.scoring import PruningEngine

    pruning = PruningEngine({'max_node_count': 5, 'min_score_threshold': 0.5})

    # Should prune low scores
    assert pruning.should_prune_node(0.1, 1, 3, 1000) == True

    # Should allow good scores
    assert pruning.should_prune_node(0.8, 1, 3, 1000) == False

    # Should prune at depth limit
    assert pruning.should_prune_node(0.8, 6, 3, 1000) == True

    # Should prune at node count limit
    assert pruning.should_prune_node(0.8, 1, 6, 1000) == True


def test_duplicate_detection():
    """Test that duplicate content is detected and skipped."""
    # Create data that will decode to the same result
    data1 = base64.b64encode(b"test content")
    data2 = base64.b64encode(b"test content")  # Same content

    engine = TitanEngine()
    report = engine.run_analysis(data1)

    # Should have decoded content
    assert any("test content" in node["content_preview"] for node in report["nodes"])

    # Reset engine and analyze duplicate
    engine.nodes = []
    report2 = engine.run_analysis(data2)

    # Should detect duplicate and not re-analyze
    duplicate_nodes = [n for n in report2["nodes"] if n.get("pruned", False)]
    assert len(duplicate_nodes) > 0