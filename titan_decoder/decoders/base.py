from abc import ABC, abstractmethod
from typing import Optional, Tuple
import base64
import gzip
import bz2
import lzma
import binascii

from ..utils.helpers import looks_like_base64, looks_like_gzip, looks_like_bz2, looks_like_hex


class Decoder(ABC):
    """Base class for all decoders."""

    @abstractmethod
    def can_decode(self, data: bytes) -> bool:
        """Check if this decoder can handle the data."""
        pass

    @abstractmethod
    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        """Decode the data. Return (decoded_data, success)."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the decoder."""
        pass


class Base64Decoder(Decoder):
    """Base64 decoder with multiline support."""

    def can_decode(self, data: bytes) -> bool:
        return looks_like_base64(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            # Handle multiline
            lines = data.splitlines()
            decoded_parts = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if looks_like_base64(line.encode()):
                    decoded_parts.append(base64.b64decode(line))
                else:
                    decoded_parts.append(line.encode())
            return b"\n".join(decoded_parts), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Base64"


class RecursiveBase64Decoder(Decoder):
    """Recursive Base64 decoder."""

    def __init__(self, max_depth: int = 3):
        self.max_depth = max_depth

    def can_decode(self, data: bytes) -> bool:
        return looks_like_base64(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        depth = 0
        current = data
        while depth < self.max_depth and looks_like_base64(current):
            try:
                current = base64.b64decode(current)
                depth += 1
            except Exception:
                break
        return current, depth > 0

    @property
    def name(self) -> str:
        return "RecursiveBase64"


class GzipDecoder(Decoder):
    """Gzip decompressor."""

    def can_decode(self, data: bytes) -> bool:
        return looks_like_gzip(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            return gzip.decompress(data), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Gzip"


class Bz2Decoder(Decoder):
    """Bz2 decompressor."""

    def can_decode(self, data: bytes) -> bool:
        return looks_like_bz2(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            return bz2.decompress(data), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Bz2"


class LzmaDecoder(Decoder):
    """LZMA/XZ decompressor."""

    def can_decode(self, data: bytes) -> bool:
        return data.startswith(b"\xfd7zXZ") or data.startswith(b"\x5d\x00\x00")

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            return lzma.decompress(data), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "LZMA"


class HexDecoder(Decoder):
    """Hex decoder."""

    def can_decode(self, data: bytes) -> bool:
        return looks_like_hex(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("ascii").strip()
            return binascii.unhexlify(text), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Hex"


class Rot13Decoder(Decoder):
    """ROT13 decoder."""

    def can_decode(self, data: bytes) -> bool:
        # Always try ROT13 as a simple cipher
        return True

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("ascii")
            decoded = ""
            for char in text:
                if 'a' <= char <= 'z':
                    decoded += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
                elif 'A' <= char <= 'Z':
                    decoded += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
                else:
                    decoded += char
            return decoded.encode("ascii"), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "ROT13"


class XorDecoder(Decoder):
    """Single-byte XOR decoder with best guess."""

    def can_decode(self, data: bytes) -> bool:
        # Always try XOR as a fallback
        return True

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        from ..utils.helpers import looks_like_text

        best_score = 0
        best_out = data
        best_key = None

        for key in range(256):
            decoded = bytes(b ^ key for b in data)
            score = sum(1 for b in decoded if 32 <= b <= 126)  # Printable ASCII
            if score > best_score:
                best_score = score
                best_key = key
                best_out = decoded

        # Only return if it looks like text and score is good
        if looks_like_text(best_out) and best_score > len(best_out) * 0.6:
            return best_out, True
        return data, False

    @property
    def name(self) -> str:
        return "XOR"