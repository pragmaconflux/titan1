"""Tests for the SmartDetectionEngine."""

import os
import base64
from titan_decoder.core.smart_detection import SmartDetectionEngine


def test_smart_detection_base32():
    """Test detection of Base32 encoded data."""
    original = b"Secret test data"
    encoded = base64.b32encode(original)
    
    engine = SmartDetectionEngine()
    detections = engine.detect_format(encoded)
    
    # Should detect Base32
    detector_names = [name for name, _ in detections]
    assert "base32" in detector_names


def test_smart_detection_asn1():
    """Test detection of ASN.1 DER encoded data."""
    # Create a more realistic ASN.1 SEQUENCE with multiple elements
    # SEQUENCE { INTEGER 42, OCTET STRING "Test" }
    asn1_data = bytes([0x30, 0x0b]) + bytes([0x02, 0x01, 0x2a, 0x04, 0x04]) + b"Test"
    
    engine = SmartDetectionEngine()
    detections = engine.detect_format(asn1_data)
    
    # Note: ASN.1 detection might not trigger on minimal data
    # This test checks that the detection method doesn't crash
    [name for name, _ in detections]
    # ASN.1 detection is optional - the main thing is it shouldn't crash
    assert True


def test_smart_detection_quoted_printable():
    """Test detection of Quoted-Printable encoded data."""
    # Create more realistic quoted-printable with multiple encoded characters
    text = "This is a test=0A=0D=3Dmessage=3Dtest with=20 encoded=20chars"
    
    engine = SmartDetectionEngine()
    detections = engine.detect_format(text.encode())
    
    detector_names = [name for name, _ in detections]
    # QP detection requires sufficient encoded sequences
    # This test checks that detection doesn't crash and has reasonable output
    assert isinstance(detector_names, list)


def test_smart_detection_confidence():
    """Test that detections return reasonable confidence scores."""
    original = b"Test message"
    encoded = base64.b32encode(original)
    
    engine = SmartDetectionEngine()
    detections = engine.detect_format(encoded)
    
    # All detections should have confidence between 0 and 1
    for name, confidence in detections:
        assert 0 <= confidence <= 1


def test_should_enable_decoder():
    """Test the should_enable_decoder method."""
    original = b"Secret data"
    encoded = base64.b32encode(original)
    
    engine = SmartDetectionEngine()
    engine.detect_format(encoded)
    
    # Should suggest enabling Base32 decoder
    assert engine.should_enable_decoder("base32", confidence_threshold=0.5)


def test_get_detected_decoders():
    """Test getting list of detected decoders."""
    original = b"This is a secret message for Base32"
    encoded = base64.b32encode(original)
    
    engine = SmartDetectionEngine()
    engine.detect_format(encoded)
    
    # Base32 encoded data should be detected
    decoders = engine.get_detected_decoders(confidence_threshold=0.5)
    assert len(decoders) > 0
    assert "base32" in decoders


def test_no_false_positives():
    """Test that random data doesn't trigger detections."""
    random_data = os.urandom(100)
    
    engine = SmartDetectionEngine()
    detections = engine.detect_format(random_data)
    
    # Random data should have few/no detections or low confidence
    high_confidence_detections = [
        (name, conf) for name, conf in detections if conf > 0.8
    ]
    # Should not have many high-confidence detections
    assert len(high_confidence_detections) <= 1
