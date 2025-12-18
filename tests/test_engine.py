import pytest
import base64
import gzip
from titan_decoder.core.engine import TitanEngine


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