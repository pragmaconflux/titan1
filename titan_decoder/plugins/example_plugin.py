"""
Example plugin for Titan Decoder Engine.

This plugin demonstrates how to create custom decoders and analyzers
for the Titan Decoder Engine.
"""

from titan_decoder.plugins import PluginDecoder, PluginAnalyzer
from typing import List, Tuple


class CustomBase32Decoder(PluginDecoder):
    """Custom Base32 decoder plugin."""

    def can_decode(self, data: bytes) -> bool:
        """Check if data looks like Base32 encoded."""
        if len(data) < 8:
            return False

        # Check for Base32 characteristics
        valid_chars = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
        sample = data[:20].upper()

        # Must contain mostly valid Base32 chars
        valid_count = sum(1 for c in sample if c in valid_chars or c in b'=\n\r\t ')
        return valid_count / len(sample) > 0.8

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        """Decode Base32 data."""
        try:
            import base64
            # Clean the data (remove whitespace)
            clean_data = b''.join(data.split())
            # Add padding if needed
            missing_padding = len(clean_data) % 8
            if missing_padding:
                clean_data += b'=' * (8 - missing_padding)

            decoded = base64.b32decode(clean_data)
            return decoded, True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "CustomBase32"

    @property
    def priority(self) -> int:
        return 5  # Higher priority than built-in decoders


class CustomHexAnalyzer(PluginAnalyzer):
    """Custom analyzer that looks for hex-encoded data patterns."""

    def can_analyze(self, data: bytes) -> bool:
        """Check if data contains hex-encoded patterns."""
        if len(data) < 10:
            return False

        # Look for hex patterns (like shellcode)
        hex_pattern = b'[0-9a-fA-F]{8,}'
        import re
        return bool(re.search(hex_pattern, data))

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Extract potential hex-encoded content."""
        results = []

        # Find hex patterns
        import re
        hex_matches = re.findall(b'[0-9a-fA-F]{8,}', data)

        for i, match in enumerate(hex_matches):
            try:
                # Try to decode as hex
                decoded = bytes.fromhex(match.decode('ascii'))
                if len(decoded) > 4:  # Only if substantial content
                    results.append((f"hex_pattern_{i}.bin", decoded))
            except:
                continue

        return results

    @property
    def name(self) -> str:
        return "CustomHexAnalyzer"

    @property
    def priority(self) -> int:
        return 3