"""Smart detection system for off-by-default decoders.

This module automatically enables decoders when specific patterns are detected,
allowing users to analyze specialized encoding formats without manual configuration.
"""

from typing import List, Tuple
import re


class SmartDetectionEngine:
    """Detects data patterns and automatically enables appropriate decoders."""

    def __init__(self):
        self.detections: List[Tuple[str, float]] = []

    def detect_format(self, data: bytes) -> List[Tuple[str, float]]:
        """
        Detect potential format encodings in the data.
        
        Args:
            data: The data to analyze
            
        Returns:
            List of (decoder_name, confidence) tuples sorted by confidence
        """
        self.detections = []

        # Run all detection methods
        self._detect_uuencode(data)
        self._detect_asn1(data)
        self._detect_quoted_printable(data)
        self._detect_base32(data)

        # Sort by confidence (highest first)
        self.detections.sort(key=lambda x: x[1], reverse=True)
        return self.detections

    def _detect_uuencode(self, data: bytes) -> None:
        """Detect UUencoded data."""
        try:
            text = data.decode("ascii", errors="ignore")
            
            # Look for UUencode header pattern
            if re.search(r'^begin\s+\d{3}\s+\w+', text, re.MULTILINE):
                # Count valid UU lines (should be 60 chars or < when encoding ends)
                lines = text.split('\n')
                uu_line_count = 0
                for line in lines:
                    if re.match(r'^[`!-_]{1,60}$', line):
                        uu_line_count += 1
                    elif line.startswith('end'):
                        break
                
                # If we found multiple valid UU lines, high confidence
                if uu_line_count >= 2:
                    confidence = min(0.95, 0.7 + (uu_line_count * 0.05))
                    self.detections.append(("uuencode", confidence))
        except Exception:
            pass

    def _detect_asn1(self, data: bytes) -> None:
        """Detect ASN.1 DER/BER encoded data."""
        if len(data) < 4:
            return

        # Check for ASN.1 SEQUENCE tag (0x30)
        if data[0] == 0x30:
            # Verify length encoding is reasonable
            length_byte = data[1]
            if length_byte & 0x80:
                # Long form - check it's not excessively long
                len_bytes = length_byte & 0x7f
                if len_bytes <= 4 and len_bytes <= len(data) - 2:
                    # Additional heuristic: check for valid tags in sequence
                    offset = 2 + len_bytes
                    if self._has_valid_asn1_tags(data[offset:]):
                        self.detections.append(("asn1", 0.85))
            elif length_byte > 0 and length_byte < len(data):
                # Short form - reasonable length
                if self._has_valid_asn1_tags(data[2:]):
                    self.detections.append(("asn1", 0.85))

    def _has_valid_asn1_tags(self, data: bytes) -> bool:
        """Check if data contains valid ASN.1 tags."""
        if len(data) < 2:
            return False
        
        # Look for common ASN.1 tags
        valid_tags = {
            0x02,  # INTEGER
            0x04,  # OCTET STRING
            0x05,  # NULL
            0x06,  # OBJECT IDENTIFIER
            0x0c,  # UTF8String
            0x13,  # PrintableString
            0x30,  # SEQUENCE
            0x31,  # SET
        }
        
        # Check first few bytes for valid tags
        count = 0
        for byte in data[:20]:
            if byte in valid_tags:
                count += 1
        
        return count >= 1

    def _detect_quoted_printable(self, data: bytes) -> None:
        """Detect Quoted-Printable encoded data."""
        try:
            text = data.decode("ascii", errors="ignore")
            
            # Look for quoted-printable patterns
            # Should have = followed by hex pairs
            qp_pattern_count = len(re.findall(r'=[0-9A-F]{2}', text, re.IGNORECASE))
            
            # Also check for soft line breaks (=\n)
            soft_breaks = len(re.findall(r'=\s*\n', text))
            
            if qp_pattern_count >= 3 or soft_breaks >= 2:
                # Check what percentage of '=' chars are followed by valid hex
                equal_count = text.count('=')
                if equal_count > 0:
                    valid_ratio = qp_pattern_count / equal_count
                    if valid_ratio >= 0.7:  # 70% of = signs should be valid QP
                        confidence = min(0.90, 0.5 + (qp_pattern_count * 0.05))
                        self.detections.append(("quoted_printable", confidence))
        except Exception:
            pass

    def _detect_base32(self, data: bytes) -> None:
        """Detect Base32 encoded data."""
        try:
            text = data.decode("ascii", errors="ignore").strip()
            
            # Base32 uses A-Z and 2-7, with optional = padding
            if re.match(r'^[A-Z2-7=]{20,}$', text):
                # Check length is multiple of 8 (or close with padding)
                content_len = len(text.rstrip('='))
                if content_len % 8 == 0 or (len(text) % 8 == 0):
                    # Calculate proportion of valid Base32 characters
                    valid_chars = sum(1 for c in text if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=')
                    valid_ratio = valid_chars / len(text)
                    
                    if valid_ratio >= 0.95:
                        confidence = min(0.88, 0.6 + (content_len / 1000))
                        self.detections.append(("base32", confidence))
        except Exception:
            pass

    def should_enable_decoder(self, decoder_name: str, confidence_threshold: float = 0.7) -> bool:
        """
        Check if a decoder should be enabled based on detected patterns.
        
        Args:
            decoder_name: Name of the decoder to check
            confidence_threshold: Minimum confidence level (0-1)
            
        Returns:
            True if decoder should be enabled
        """
        for detected_name, confidence in self.detections:
            if detected_name == decoder_name and confidence >= confidence_threshold:
                return True
        return False

    def get_detected_decoders(self, confidence_threshold: float = 0.7) -> List[str]:
        """Get list of decoders that should be enabled based on detections."""
        return [
            name for name, conf in self.detections
            if conf >= confidence_threshold
        ]
