from abc import ABC, abstractmethod
from typing import Tuple
import base64
import gzip
import bz2
import lzma
import binascii
import re

from ..utils.helpers import (
    looks_like_base64,
    looks_like_gzip,
    looks_like_bz2,
    looks_like_hex,
)


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


class ZlibDecoder(Decoder):
    """ZLIB decompressor."""

    def can_decode(self, data: bytes) -> bool:
        # ZLIB compressed data typically starts with compression method
        # This is a heuristic - ZLIB doesn't have a fixed header like GZIP
        if len(data) < 2:
            return False
        # Check for ZLIB header (compression method and flags)
        # First byte: Compression method (8 = deflate)
        # Second byte: Flags
        compression_method = data[0] & 0x0F
        return compression_method == 8  # Deflate compression

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            import zlib

            return zlib.decompress(data), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "ZLIB"


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
        """Only try ROT13 if data looks like it might be text."""
        if len(data) < 8:
            return False

        # If it already looks like base64, prefer Base64/RecursiveBase64.
        # ROT13 on base64-like payloads is almost always a false-positive.
        if looks_like_base64(data):
            return False

        # Try to decode as ASCII
        try:
            text = data.decode("ascii")
        except UnicodeDecodeError:
            return False

        # Check if it looks like it could be English or common text
        # Count letters (a-z, A-Z)
        letter_count = sum(1 for c in text if c.isalpha())
        if letter_count < len(text) * 0.3:  # At least 30% should be letters
            return False

        # Check that most characters are printable
        printable_count = sum(1 for c in text if c.isprintable() or c.isspace())
        if printable_count < len(text) * 0.9:
            return False

        return True

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("ascii")
            decoded = ""
            for char in text:
                if "a" <= char <= "z":
                    decoded += chr((ord(char) - ord("a") + 13) % 26 + ord("a"))
                elif "A" <= char <= "Z":
                    decoded += chr((ord(char) - ord("A") + 13) % 26 + ord("A"))
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
        """Check if data might be XOR encoded."""
        if len(data) < 8:
            return False

        # Check if data has some structure that suggests XOR encoding
        # Look for patterns that are common in XOR-encoded data
        # High entropy but some repeating patterns
        diversity = len(set(data)) / len(data)
        if diversity < 0.5:  # Low diversity suggests not XOR
            return False

        # Check for potential XOR patterns (like English text with high bit set)
        high_bit_count = sum(1 for b in data if b & 0x80)
        high_bit_ratio = high_bit_count / len(data)
        if high_bit_ratio < 0.1:  # Not enough high bits
            return False

        return True

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        from ..utils.helpers import looks_like_text

        best_score = 0
        best_out = data

        for key in range(256):
            decoded = bytes(b ^ key for b in data)
            score = sum(1 for b in decoded if 32 <= b <= 126)  # Printable ASCII
            if score > best_score:
                best_score = score
                best_out = decoded

        # Only return if it looks like text and score is good
        if looks_like_text(best_out) and best_score > len(best_out) * 0.6:
            return best_out, True
        return data, False

    @property
    def name(self) -> str:
        return "XOR"


class PDFDecoder(Decoder):
    """PDF file stream decoder - extracts compressed streams and objects."""

    def __init__(self):
        pass

    def can_decode(self, data: bytes) -> bool:
        """Check if data looks like a PDF file."""
        result = data.startswith(b"%PDF-") and b"%%EOF" in data
        return result

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        """Extract and decompress PDF streams and objects."""
        try:
            extracted_content = []

            # Find all stream objects with their preceding dictionaries
            # Pattern matches: <<...>> stream ... endstream
            stream_pattern = b"<<([^>]*)>>\\s*stream\\r?\\n(.*?)\\r?\\nendstream"
            import re

            matches = re.findall(stream_pattern, data, re.DOTALL)

            for dict_part, stream_data in matches:
                # Check if this stream uses FlateDecode compression
                if b"/FlateDecode" in dict_part:
                    try:
                        import zlib

                        decompressed = zlib.decompress(stream_data)
                        extracted_content.append(decompressed)
                    except Exception:
                        # If decompression fails, keep original
                        extracted_content.append(stream_data)
                else:
                    extracted_content.append(stream_data)

            # Also extract JavaScript if present
            js_pattern = b"/JavaScript\\s*(.*?)\\s*endobj"
            js_matches = re.findall(js_pattern, data, re.DOTALL | re.IGNORECASE)
            for js in js_matches:
                extracted_content.append(js.strip())

            # Extract embedded files
            embedded_pattern = b"/EmbeddedFile\\s*(.*?)\\s*endobj"
            embedded_matches = re.findall(
                embedded_pattern, data, re.DOTALL | re.IGNORECASE
            )
            for embedded in embedded_matches:
                extracted_content.append(embedded.strip())

            if extracted_content:
                # Return concatenated extracted content
                return b"\n".join(extracted_content), True

            return data, False

        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "PDF"


class OLEDecoder(Decoder):
    """OLE (Object Linking and Embedding) file decoder - extracts embedded content."""

    def can_decode(self, data: bytes) -> bool:
        """Check if data looks like an OLE file."""
        if len(data) < 8:
            return False
        # OLE signature: D0 CF 11 E0 A1 B1 1A E1
        return data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        """Extract embedded content from OLE files."""
        try:
            extracted_content = []

            # Basic OLE parsing - look for common embedded content patterns
            # This is a simplified implementation

            # Look for embedded OLE objects
            ole_objects = self._extract_ole_objects(data)
            extracted_content.extend(ole_objects)

            # Look for VBA macros (common in malicious Office docs)
            vba_content = self._extract_vba_macros(data)
            if vba_content:
                extracted_content.extend(vba_content)

            # Look for embedded files
            embedded_files = self._extract_embedded_files(data)
            extracted_content.extend(embedded_files)

            if extracted_content:
                return b"\n".join(extracted_content), True

            return data, False

        except Exception:
            return data, False

    def _extract_ole_objects(self, data: bytes) -> list:
        """Extract OLE objects from the file."""
        objects = []

        # Look for OLE object signatures
        ole_signatures = [
            b"\x01\x00\x00\x00",  # OLE object
            b"Package",  # Embedded package
        ]

        for sig in ole_signatures:
            pos = 0
            while True:
                pos = data.find(sig, pos)
                if pos == -1:
                    break

                # Extract reasonable amount of data after signature
                start = max(0, pos - 100)
                end = min(len(data), pos + 1000)
                objects.append(data[start:end])
                pos += len(sig)

        return objects

    def _extract_vba_macros(self, data: bytes) -> list:
        """Extract VBA macro content."""
        macros = []

        # Look for VBA project signatures
        vba_indicators = [b"VBA", b"PROJECT", b"Attribute VB_Name"]

        for indicator in vba_indicators:
            pos = 0
            while True:
                pos = data.find(indicator, pos)
                if pos == -1:
                    break

                # Extract macro content (look for reasonable boundaries)
                start = pos
                # Look for end markers
                end_markers = [b"\x00\x00", b"End Sub", b"End Function"]
                end = len(data)

                for marker in end_markers:
                    marker_pos = data.find(marker, pos)
                    if marker_pos != -1 and marker_pos < end:
                        end = marker_pos + len(marker)

                macro_content = data[start:end]
                if len(macro_content) > 10:  # Only if substantial content
                    macros.append(macro_content)

                pos += len(indicator)

        return macros

    def _extract_embedded_files(self, data: bytes) -> list:
        """Extract embedded files from OLE containers."""
        files = []

        # Look for file headers within the OLE data
        file_headers = [
            b"%PDF-",  # PDF
            b"PK\x03\x04",  # ZIP
            b"MZ",  # PE
            b"\x7fELF",  # ELF
            b"BZ",  # BZIP2
            b"\x1f\x8b",  # GZIP
        ]

        for header in file_headers:
            pos = 0
            while True:
                pos = data.find(header, pos)
                if pos == -1:
                    break

                # Extract from header to a reasonable size
                start = pos
                end = min(len(data), pos + 10000)  # 10KB should be enough for headers
                files.append(data[start:end])
                pos += len(header)

        return files

    @property
    def name(self) -> str:
        return "OLE"


class UUDecoder(Decoder):
    """UUencode decoder - OFF BY DEFAULT (enables smart detection)."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def can_decode(self, data: bytes) -> bool:
        if not self.enabled:
            return False

        try:
            text = data.decode("ascii")
            # UUencoded data starts with "begin" followed by permissions and filename
            return bool(re.match(r"^begin\s+\d{3}\s+\w+", text, re.MULTILINE))
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            import uu
            import io

            # Create a buffer and attempt UU decode
            input_buffer = io.BytesIO(data)
            output_buffer = io.BytesIO()

            uu.decode(input_buffer, output_buffer)
            decoded = output_buffer.getvalue()

            return decoded if decoded else (data, False), bool(decoded)
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "UUEncode"


class ASN1Decoder(Decoder):
    """ASN.1 DER/BER decoder - OFF BY DEFAULT (enables smart detection)."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def can_decode(self, data: bytes) -> bool:
        if not self.enabled:
            return False

        # ASN.1 typically starts with tag 0x30 (SEQUENCE)
        if len(data) < 4:
            return False

        # Check for common ASN.1 DER/BER signatures
        if data[0] in (
            0x30,
            0x31,
            0x02,
            0x06,
        ):  # SEQUENCE, SET, INTEGER, OBJECT IDENTIFIER
            # Verify length encoding
            if data[1] & 0x80:
                # Long form length
                return data[1] & 0x7F <= 4  # Reasonable length encoding
            return True

        return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            # Basic ASN.1 parsing - extract readable content
            decoded_content = self._parse_asn1(data)
            if decoded_content:
                return decoded_content, True
            return data, False
        except Exception:
            return data, False

    def _parse_asn1(self, data: bytes, depth: int = 0) -> bytes:
        """Recursively parse ASN.1 structure."""
        if depth > 10 or len(data) < 2:
            return b""

        result = []
        offset = 0

        while offset < len(data):
            # Parse tag
            tag = data[offset]
            offset += 1

            if offset >= len(data):
                break

            # Parse length
            length = data[offset]
            offset += 1

            if length & 0x80:
                # Long form
                len_bytes = length & 0x7F
                if offset + len_bytes > len(data):
                    break
                length = int.from_bytes(data[offset : offset + len_bytes], "big")
                offset += len_bytes

            # Extract value
            if offset + length > len(data):
                break

            value = data[offset : offset + length]
            offset += length

            # Try to extract printable content
            try:
                if tag == 0x04:  # OCTET STRING
                    result.append(value)
                elif tag == 0x0C:  # UTF8String
                    result.append(value)
                elif tag == 0x13:  # PrintableString
                    result.append(value)
            except Exception:
                pass

        return b"\n".join(result)

    @property
    def name(self) -> str:
        return "ASN.1"


class QuotedPrintableDecoder(Decoder):
    """Quoted-Printable decoder - OFF BY DEFAULT (enables smart detection)."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def can_decode(self, data: bytes) -> bool:
        if not self.enabled:
            return False

        try:
            text = data.decode("ascii")
            # Look for typical quoted-printable patterns
            return "=" in text and re.search(r"=[0-9A-F]{2}", text, re.IGNORECASE)
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            import quopri

            decoded = quopri.decodestring(data)
            return decoded if decoded != data else (data, False), decoded != data
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "QuotedPrintable"


class Base32Decoder(Decoder):
    """Base32 decoder - OFF BY DEFAULT (enables smart detection)."""

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def can_decode(self, data: bytes) -> bool:
        if not self.enabled:
            return False

        try:
            text = data.decode("ascii").strip()
            # Base32 uses A-Z and 2-7, typically multiple of 8
            if not re.match(r"^[A-Z2-7=]+$", text):
                return False
            if len(text) % 8 != 0 and len(text) % 8 != 7:  # Allow for missing padding
                return False
            return len(text) >= 16  # Need reasonable length
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            import base64

            text = data.decode("ascii").strip()
            # Add padding if needed
            padding = (8 - len(text) % 8) % 8
            text += "=" * padding
            decoded = base64.b32decode(text)
            return decoded, True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Base32"


class URLDecoder(Decoder):
    """URL percent-encoding decoder."""

    def can_decode(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="ignore")
            return bool(re.search(r"%[0-9A-Fa-f]{2}", text))
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("utf-8", errors="ignore")
            result = b""
            i = 0
            while i < len(text):
                if text[i] == "%" and i + 2 < len(text):
                    try:
                        byte_val = int(text[i + 1 : i + 3], 16)
                        result += bytes([byte_val])
                        i += 3
                    except ValueError:
                        result += text[i].encode("utf-8")
                        i += 1
                elif text[i] == "+":
                    result += b" "
                    i += 1
                else:
                    result += text[i].encode("utf-8")
                    i += 1
            return result if result else data, bool(result and result != data)
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "URLDecoder"


class HTMLEntityDecoder(Decoder):
    """HTML entity decoder."""

    def can_decode(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="ignore")
            return bool(
                re.search(r"&#(?:\d+|x[0-9A-Fa-f]+);|&[a-z]+;", text, re.IGNORECASE)
            )
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("utf-8", errors="ignore")
            result = []
            i = 0

            entities = {
                "nbsp": 0x20,
                "lt": ord("<"),
                "gt": ord(">"),
                "amp": ord("&"),
                "quot": ord('"'),
                "apos": ord("'"),
            }

            while i < len(text):
                if text[i] == "&":
                    # Try numeric
                    match_dec = re.match(r"&#(\d+);", text[i:])
                    match_hex = re.match(r"&#x([0-9A-Fa-f]+);", text[i:], re.IGNORECASE)

                    if match_dec:
                        try:
                            code = int(match_dec.group(1))
                            result.append(chr(code))
                            i += len(match_dec.group(0))
                            continue
                        except (ValueError, OverflowError):
                            pass
                    elif match_hex:
                        try:
                            code = int(match_hex.group(1), 16)
                            result.append(chr(code))
                            i += len(match_hex.group(0))
                            continue
                        except (ValueError, OverflowError):
                            pass

                    # Try named
                    match_named = re.match(r"&([a-z]+);", text[i:], re.IGNORECASE)
                    if match_named:
                        entity_name = match_named.group(1).lower()
                        if entity_name in entities:
                            result.append(chr(entities[entity_name]))
                            i += len(match_named.group(0))
                            continue

                result.append(text[i])
                i += 1

            decoded = "".join(result).encode("utf-8")
            return decoded, decoded != data
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "HTMLEntity"


class UnicodeEscapeDecoder(Decoder):
    """Unicode escape sequences decoder."""

    def can_decode(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="ignore")
            return bool(re.search(r"\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}", text))
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("utf-8", errors="ignore")
            result = []
            i = 0

            while i < len(text):
                # Try \\UXXXXXXXX
                if text[i : i + 2] == "\\U" and i + 10 <= len(text):
                    try:
                        code = int(text[i + 2 : i + 10], 16)
                        result.append(chr(code))
                        i += 10
                        continue
                    except (ValueError, OverflowError):
                        pass

                # Try \\uXXXX
                if text[i : i + 2] == "\\u" and i + 6 <= len(text):
                    try:
                        code = int(text[i + 2 : i + 6], 16)
                        result.append(chr(code))
                        i += 6
                        continue
                    except (ValueError, OverflowError):
                        pass

                result.append(text[i])
                i += 1

            decoded = "".join(result).encode("utf-8")
            return decoded, decoded != data
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "UnicodeEscape"
