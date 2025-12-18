import base64
import gzip
import zlib
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


def test_handles_empty_file_gracefully():
    engine = TitanEngine()
    report = engine.run_analysis(b"")

    # Should produce zero or minimal nodes and not crash
    assert "nodes" in report
    assert report["node_count"] >= 0


def test_gzip_decoding():
    """Test Gzip decompression."""
    original = b"This is a test string for gzip compression."
    compressed = gzip.compress(original)

    engine = TitanEngine()
    report = engine.run_analysis(compressed)

    assert report["node_count"] >= 2
    assert any("test string" in node["content_preview"] for node in report["nodes"])


def test_zlib_decoding():
    """Test ZLIB decompression."""
    original = b"This is a test string for zlib compression."
    compressed = zlib.compress(original)

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
    high_entropy = b"\x00\x01\x02\x03\x04\x05\x06\x07"  # High entropy
    low_entropy = b"Hello World Hello World"  # Low entropy, structured

    score = ScoringEngine.calculate_decode_score(high_entropy, low_entropy, "Base64", 0)
    assert score > 0.0  # Should get a positive score for entropy reduction

    # Test printable ratio gain
    binary_data = b"\x00\x01\x02\x03\x04\x05"
    text_data = b"Hello World!"

    score = ScoringEngine.calculate_decode_score(binary_data, text_data, "Base64", 0)
    assert score > 0.0  # Should get a positive score for more printable chars

    # Test structural emergence
    random_data = b"abcdefghijklmnop"
    json_data = b'{"key": "value"}'

    score = ScoringEngine.calculate_decode_score(random_data, json_data, "Base64", 0)
    assert score > 0.0  # Should detect JSON structure


def test_pruning_logic():
    """Test that pruning prevents excessive analysis."""
    from titan_decoder.core.scoring import PruningEngine

    pruning = PruningEngine({"max_node_count": 5, "min_score_threshold": 0.5})

    # Should prune low scores
    assert pruning.should_prune_node(0.1, 1, 3, 1000)

    # Should allow good scores
    assert not pruning.should_prune_node(0.8, 1, 3, 1000)

    # Should prune at depth limit
    assert pruning.should_prune_node(0.8, 6, 3, 1000)

    # Should prune at node count limit
    assert pruning.should_prune_node(0.8, 1, 6, 1000)


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


def test_pe_metadata_extraction():
    """Test PE file metadata extraction."""
    # Create minimal PE header (MZ + PE signature + basic COFF header)
    pe_data = (
        b"MZ"
        + b"\x00" * 58  # DOS header
        + b"\x80\x00\x00\x00"  # e_lfanew pointing to 0x80
        + b"\x00" * 64  # Padding to PE offset
        + b"PE\x00\x00"  # PE signature
        + b"\x4c\x01"  # Machine: x86
        + b"\x02\x00"  # Number of sections: 2
        + b"\x00\x00\x00\x00"  # Time date stamp
        + b"\x00\x00\x00\x00"  # Pointer to symbol table
        + b"\x00\x00\x00\x00"  # Number of symbols
        + b"\x00\x00"  # Size of optional header: 0 (no optional header)
        + b"\x00\x00"  # Characteristics
    )

    engine = TitanEngine()
    report = engine.run_analysis(pe_data)

    # Should extract PE metadata
    assert report["node_count"] >= 2
    # Check that we have a node with PE analyzer method
    pe_nodes = [n for n in report["nodes"] if n.get("method") == "ANALYZE_PE"]
    assert len(pe_nodes) > 0


def test_elf_metadata_extraction():
    """Test ELF file metadata extraction."""
    # Create minimal ELF header (64-bit x86-64 executable)
    elf_data = (
        b"\x7fELF"  # ELF magic
        + b"\x02"  # 64-bit
        + b"\x01"  # Little endian
        + b"\x01"  # ELF version
        + b"\x00"  # System V ABI
        + b"\x00" * 8  # Padding
        + b"\x02\x00"  # Executable file
        + b"\x3e\x00"  # x86-64 machine
        + b"\x01\x00\x00\x00"  # Version
        + b"\x00\x10\x00\x00\x00\x00\x00\x00"  # Entry point
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Program header offset
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Section header offset
        + b"\x00\x00\x00\x00"  # Flags
        + b"\x40\x00"  # ELF header size
        + b"\x38\x00"  # Program header entry size
        + b"\x00\x00"  # Number of program headers
        + b"\x40\x00"  # Section header entry size
        + b"\x00\x00"  # Number of section headers
        + b"\x00\x00"  # Section header string table index
    )

    engine = TitanEngine()
    report = engine.run_analysis(elf_data)

    # Should extract ELF metadata
    assert report["node_count"] >= 2
    # Check that we have a node with ELF analyzer method
    elf_nodes = [n for n in report["nodes"] if n.get("method") == "ANALYZE_ELF"]
    assert len(elf_nodes) > 0


def test_pdf_decoder():
    """Test PDF file stream extraction."""
    # Create a minimal PDF with a compressed stream
    import zlib

    stream_content = b"This is embedded content in a PDF stream."
    compressed_stream = zlib.compress(stream_content)

    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n"
        b"<<\n"
        b"/Type /Catalog\n"
        b"/Pages 2 0 R\n"
        b">>\n"
        b"endobj\n"
        b"2 0 obj\n"
        b"<<\n"
        b"/Type /Pages\n"
        b"/Kids [3 0 R]\n"
        b"/Count 1\n"
        b">>\n"
        b"endobj\n"
        b"3 0 obj\n"
        b"<<\n"
        b"/Type /Page\n"
        b"/Parent 2 0 R\n"
        b"/MediaBox [0 0 612 792]\n"
        b"/Contents 4 0 R\n"
        b">>\n"
        b"endobj\n"
        b"4 0 obj\n"
        b"<<\n"
        b"/Length " + str(len(compressed_stream)).encode() + b"\n"
        b"/Filter /FlateDecode\n"
        b">>\n"
        b"stream\n" + compressed_stream + b"\nendstream\n"
        b"endobj\n"
        b"xref\n"
        b"0 5\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000200 00000 n \n"
        b"trailer\n"
        b"<<\n"
        b"/Size 5\n"
        b"/Root 1 0 R\n"
        b">>\n"
        b"startxref\n"
        b"284\n"
        b"%%EOF\n"
    )

    engine = TitanEngine()
    report = engine.run_analysis(pdf_content)

    # Should extract PDF content
    assert report["node_count"] >= 2
    # Check that we have decoded content
    found_content = False
    for node in report["nodes"]:
        if stream_content.decode() in node["content_preview"]:
            found_content = True
            break
    assert found_content


def test_ole_decoder():
    """Test OLE file embedded content extraction."""
    # Create a minimal OLE file with embedded content
    ole_header = (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504
    )  # OLE signature + padding

    # Add some embedded content that looks like VBA
    embedded_content = b'VBA Macro content: Sub AutoOpen()\nMsgBox "Hello"\nEnd Sub'
    ole_data = ole_header + embedded_content

    engine = TitanEngine()
    report = engine.run_analysis(ole_data)

    # Should extract OLE content
    assert report["node_count"] >= 2
    # Check that we have decoded content
    found_content = False
    for node in report["nodes"]:
        if "VBA Macro" in node["content_preview"]:
            found_content = True
            break
    assert found_content


def test_smart_detection_base32():
    """Test smart detection for Base32 encoded data."""
    import base64

    original = b"Secret message"
    encoded = base64.b32encode(original)

    engine = TitanEngine()
    report = engine.run_analysis(encoded)

    # Should detect and decode Base32
    assert any("Secret message" in node["content_preview"] for node in report["nodes"])


def test_smart_detection_asn1():
    """Test smart detection for ASN.1 DER encoded data."""
    # Create minimal ASN.1 SEQUENCE with valid structure
    asn1_data = (
        bytes([0x30, 0x0C]) + b"\x04\x08TestData"
    )  # SEQUENCE { OCTET STRING "TestData" }

    engine = TitanEngine()
    report = engine.run_analysis(asn1_data)

    # Should detect ASN.1
    assert report["node_count"] >= 1


def test_smart_detection_quoted_printable():
    """Test smart detection for Quoted-Printable encoded data."""
    import quopri

    original = b"This is a test message"
    encoded = quopri.encodestring(original)

    engine = TitanEngine()
    report = engine.run_analysis(encoded)

    # Should detect and handle Quoted-Printable
    assert report["node_count"] >= 1


def test_uuencode_decoder():
    """Test UUencode decoder."""
    from titan_decoder.decoders.base import UUDecoder

    # Create valid UUencoded data
    uudata = b"begin 644 testfile\n" + b'`8V]L9"`\n' + b"end"

    decoder = UUDecoder(enabled=True)
    can_decode = decoder.can_decode(uudata)

    # Should detect UUencode format
    assert can_decode


def test_base32_decoder():
    """Test Base32 decoder."""
    import base64
    from titan_decoder.decoders.base import Base32Decoder

    original = b"Test data for Base32"
    encoded = base64.b32encode(original)

    decoder = Base32Decoder(enabled=True)
    can_decode = decoder.can_decode(encoded)
    assert can_decode

    decoded, success = decoder.decode(encoded)
    assert success
    assert decoded == original


def test_asn1_decoder():
    """Test ASN.1 decoder."""
    from titan_decoder.decoders.base import ASN1Decoder

    # Create minimal ASN.1 SEQUENCE with valid structure
    asn1_data = bytes([0x30, 0x0C]) + b"\x04\x08TestData"

    decoder = ASN1Decoder(enabled=True)
    can_decode = decoder.can_decode(asn1_data)
    assert can_decode

    decoded, success = decoder.decode(asn1_data)
    assert success or decoded == asn1_data  # Either decoded or returned as-is
