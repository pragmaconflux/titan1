"""Advanced heuristics: entropy analysis, XOR key finding, deobfuscation."""

import math
from typing import List, Dict, Tuple
from collections import Counter


class EntropyAnalyzer:
    """Analyze Shannon entropy and detect packed/encrypted data."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data (0-8)."""
        if not data:
            return 0.0
        counts = Counter(data)
        entropy = -sum(
            (count / len(data)) * math.log2(count / len(data))
            for count in counts.values()
        )
        return entropy

    @staticmethod
    def is_packed(data: bytes) -> Tuple[bool, float]:
        """Detect if data is likely packed/encrypted.

        Returns: (is_packed, confidence)
        - Entropy > 7.0 strongly suggests compression/encryption
        - Entropy < 5.0 suggests plaintext/structured data
        """
        entropy = EntropyAnalyzer.calculate_entropy(data)

        # High entropy indicates compression or encryption
        if entropy > 7.0:
            return True, min(1.0, (entropy - 7.0) / 1.0)
        elif entropy > 6.5:
            return True, 0.5
        else:
            return False, 0.0

    @staticmethod
    def get_byte_distribution(data: bytes) -> Dict[int, int]:
        """Get frequency distribution of bytes."""
        return dict(Counter(data))

    @staticmethod
    def analyze(data: bytes) -> Dict[str, float]:
        """Comprehensive entropy analysis."""
        entropy = EntropyAnalyzer.calculate_entropy(data)
        is_packed, pack_confidence = EntropyAnalyzer.is_packed(data)

        # Calculate chi-squared statistic (uniform distribution test)
        distribution = EntropyAnalyzer.get_byte_distribution(data)
        expected_count = len(data) / 256
        chi_squared = sum(
            (count - expected_count) ** 2 / expected_count
            for count in distribution.values()
        )

        return {
            "entropy": entropy,
            "is_packed": is_packed,
            "pack_confidence": pack_confidence,
            "chi_squared": chi_squared,
            "byte_count": len(distribution),  # Unique bytes
            "uniformity": min(
                1.0, 256 / (chi_squared + 1)
            ),  # Closer to 1 = more uniform
        }


class XORKeyFinder:
    """Find XOR keys and single-byte XOR deobfuscation."""

    @staticmethod
    def find_xor_keys(data: bytes, sample_size: int = 512) -> List[Tuple[int, float]]:
        """Find likely XOR keys by entropy analysis.

        Returns: List of (key, confidence) sorted by confidence.
        """
        if len(data) < 4:
            return []

        # Sample data for performance
        sample = data[: min(len(data), sample_size)]
        results = []

        for key in range(256):
            # XOR with candidate key
            xored = bytes(b ^ key for b in sample)

            # Calculate metrics
            entropy = EntropyAnalyzer.calculate_entropy(xored)
            Counter(xored)

            # Count printable characters (heuristic for plaintext)
            printable = sum(1 for b in xored if 32 <= b <= 126 or b in (9, 10, 13))
            printable_ratio = printable / len(xored)

            # Score: favor lower entropy + high printable ratio
            entropy_score = 1.0 - (entropy / 8.0)  # Lower entropy = higher score
            printable_score = printable_ratio

            confidence = (entropy_score * 0.4) + (printable_score * 0.6)

            if confidence > 0.3:  # Only return promising keys
                results.append((key, confidence))

        return sorted(results, key=lambda x: x[1], reverse=True)

    @staticmethod
    def xor_decode(data: bytes, key: int) -> bytes:
        """Decode single-byte XOR."""
        return bytes(b ^ key for b in data)

    @staticmethod
    def try_xor_keys(data: bytes, top_n: int = 3) -> List[Dict]:
        """Try top N XOR keys and return results."""
        keys = XORKeyFinder.find_xor_keys(data)[:top_n]
        results = []

        for key, confidence in keys:
            decoded = XORKeyFinder.xor_decode(data, key)
            results.append(
                {
                    "key": key,
                    "key_hex": hex(key),
                    "confidence": confidence,
                    "decoded": decoded,
                    "entropy": EntropyAnalyzer.calculate_entropy(decoded),
                }
            )

        return results


class StringDeobfuscator:
    """Extract and deobfuscate strings from binary data."""

    @staticmethod
    def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract readable ASCII/UTF-8 strings."""
        strings = []
        current = bytearray()

        for byte in data:
            # Include ASCII printable + common control chars
            if (32 <= byte <= 126) or byte in (9, 10, 13):
                current.append(byte)
            else:
                if len(current) >= min_length:
                    try:
                        strings.append(current.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass
                current = bytearray()

        if len(current) >= min_length:
            try:
                strings.append(current.decode("utf-8", errors="ignore"))
            except Exception:
                pass

        return strings

    @staticmethod
    def extract_unicode_strings(data: bytes, min_length: int = 4) -> List[str]:
        """Extract UTF-16LE/UTF-16BE strings (common in Windows)."""
        strings = []

        # Try UTF-16LE
        try:
            text = data.decode("utf-16-le", errors="ignore")
            strings.extend([s for s in text.split("\x00") if len(s) >= min_length])
        except Exception:
            pass

        # Try UTF-16BE
        try:
            text = data.decode("utf-16-be", errors="ignore")
            strings.extend([s for s in text.split("\x00") if len(s) >= min_length])
        except Exception:
            pass

        return list(set(strings))  # Deduplicate

    @staticmethod
    def deobfuscate_strings(data: bytes) -> Dict[str, List[str]]:
        """Extract ASCII, Unicode, and potentially encoded strings."""
        return {
            "ascii": StringDeobfuscator.extract_strings(data, min_length=4),
            "unicode": StringDeobfuscator.extract_unicode_strings(data, min_length=4),
            "suspicious_patterns": StringDeobfuscator._find_patterns(data),
        }

    @staticmethod
    def _find_patterns(data: bytes) -> List[str]:
        """Find suspicious patterns: URLs, IPs, emails."""
        import re

        strings = StringDeobfuscator.extract_strings(data)
        text = "\n".join(strings)

        patterns = {
            "urls": re.findall(r"https?://\S+", text),
            "domains": re.findall(
                r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}",
                text,
                re.IGNORECASE,
            ),
            "emails": re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text),
            "ips": re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text),
        }

        result = []
        for ptype, matches in patterns.items():
            for match in matches:
                result.append(f"{ptype}: {match}")
        return result


class PolymorphicFingerprinting:
    """Detect polymorphic malware variants."""

    @staticmethod
    def calculate_ssdeep_hash(data: bytes) -> str:
        """Simplified fuzzy hash (context triggered piecewise hashing concept).

        Returns a hash that's similar for similar data despite variations.
        """
        import hashlib

        # Simple rolling hash approach
        chunk_size = max(64, len(data) // 8)
        chunks = []

        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            h = hashlib.md5(chunk).hexdigest()[:8]
            chunks.append(h)

        return ":".join(chunks)

    @staticmethod
    def similarity_score(hash1: str, hash2: str) -> float:
        """Compare two fuzzy hashes. Returns 0-1 (1 = identical)."""
        chunks1 = hash1.split(":")
        chunks2 = hash2.split(":")

        if not chunks1 or not chunks2:
            return 0.0

        matches = sum(1 for c1, c2 in zip(chunks1, chunks2) if c1 == c2)
        return matches / max(len(chunks1), len(chunks2))

    @staticmethod
    def analyze_polymorphism(data: bytes) -> Dict:
        """Analyze data for polymorphic characteristics."""
        entropy = EntropyAnalyzer.calculate_entropy(data)
        xor_keys = XORKeyFinder.find_xor_keys(data, sample_size=256)

        # High entropy + multiple viable XOR keys = likely polymorphic
        is_polymorphic = entropy > 6.5 and len(xor_keys) >= 3

        return {
            "entropy": entropy,
            "xor_keys_found": len(xor_keys),
            "is_polymorphic": is_polymorphic,
            "confidence": min(1.0, entropy / 7.0) * (1.0 if len(xor_keys) > 0 else 0.5),
            "ssdeep": PolymorphicFingerprinting.calculate_ssdeep_hash(data),
        }
