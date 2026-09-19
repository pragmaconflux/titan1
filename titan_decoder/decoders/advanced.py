"""Bounded decoders for common malware transport and script encodings.

Every decoder in this module is static: it transforms bytes and never imports,
opens, or executes recovered content.  Heuristics are deliberately strict so
ordinary prose is not reinterpreted as an encoded payload.
"""

from __future__ import annotations

import base64
import binascii
import io
import re
import zlib

from .base import Decoder, DEFAULT_MAX_DECOMPRESSED_SIZE
from ..core.emulation import JavaScriptConstantEvaluator
from ..utils.helpers import looks_meaningful_payload as _meaningful_output


class Ascii85Decoder(Decoder):
    """Decode Adobe ASCII85/Base85 payloads with explicit framing."""

    _PREFIXES = (b"ascii85:", b"base85:")

    @property
    def name(self) -> str:
        return "ASCII85"

    def _candidate(self, data: bytes) -> tuple[bytes, bool] | None:
        value = b"".join(data.strip().split())
        lowered = value.lower()
        for prefix in self._PREFIXES:
            if lowered.startswith(prefix):
                return value[len(prefix) :], False
        if value.startswith(b"<~") and value.endswith(b"~>"):
            return value, True
        return None

    def can_decode(self, data: bytes) -> bool:
        candidate = self._candidate(data)
        if candidate is None or len(candidate[0]) < 5:
            return False
        decoded, success = self.decode(data)
        return success and decoded != data

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        candidate = self._candidate(data)
        if candidate is None:
            return data, False
        value, adobe = candidate
        try:
            decoded = base64.a85decode(value, adobe=adobe, ignorechars=b" \t\r\n")
        except (ValueError, binascii.Error, OverflowError):
            return data, False
        return (decoded, True) if decoded and decoded != data else (data, False)


class RawDeflateDecoder(Decoder):
    """Decode raw RFC 1951 DEFLATE streams without a zlib wrapper."""

    def __init__(self, max_output: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output = max(1, int(max_output))

    @property
    def name(self) -> str:
        return "RawDeflate"

    def _decode(self, data: bytes) -> bytes | None:
        if len(data) < 5:
            return None
        try:
            decoder = zlib.decompressobj(-zlib.MAX_WBITS)
            output = decoder.decompress(data, self.max_output + 1)
            # Raw DEFLATE has no header, so the only defensible signal is that
            # the entire input is one complete stream: bytes left after EOF
            # land in unused_data and mean the "stream" was a coincidental
            # prefix (ordinary text such as "{\n ..." decodes this way).
            if (
                len(output) > self.max_output
                or decoder.unconsumed_tail
                or decoder.unused_data
                or not decoder.eof
            ):
                return None
            output += decoder.flush(self.max_output + 1 - len(output))
            if len(output) > self.max_output:
                return None
            return output or None
        except (ValueError, zlib.error):
            return None

    def can_decode(self, data: bytes) -> bool:
        decoded = self._decode(data)
        return bool(decoded and decoded != data)

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        decoded = self._decode(data)
        return (decoded, True) if decoded and decoded != data else (data, False)


class PowerShellEncodedCommandDecoder(Decoder):
    """Extract and decode a PowerShell ``-EncodedCommand`` argument."""

    _PATTERN = re.compile(
        r"(?is)\b(?:powershell|pwsh)(?:\.exe)?\b.{0,96}?"
        r"(?:-|/)(?:e|en|enc|enco|encodedcommand)\s+['\"]?"
        r"([A-Za-z0-9+/]{12,}={0,2})"
    )

    @property
    def name(self) -> str:
        return "PowerShellEncodedCommand"

    def _decode(self, data: bytes) -> bytes | None:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        match = self._PATTERN.search(text)
        if match is None:
            return None
        encoded = match.group(1).encode("ascii")
        try:
            raw = base64.b64decode(encoded + b"=" * (-len(encoded) % 4), validate=True)
            command = raw.decode("utf-16-le").lstrip("\ufeff").encode("utf-8")
        except (ValueError, UnicodeDecodeError, binascii.Error):
            return None
        return command if _meaningful_output(command) else None

    def can_decode(self, data: bytes) -> bool:
        return self._decode(data) is not None

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        decoded = self._decode(data)
        return (decoded, True) if decoded and decoded != data else (data, False)


class JavaScriptEscapeDecoder(Decoder):
    """Normalize common JavaScript escape and ``fromCharCode`` obfuscation."""

    _FROM_CHAR_CODE = re.compile(
        r"(?i)(?:String\s*\.\s*)?fromCharCode\s*\(([^)]{1,4096})\)"
    )
    _ESCAPE = re.compile(r"%u([0-9A-Fa-f]{4})|%([0-9A-Fa-f]{2})|\\x([0-9A-Fa-f]{2})")
    _STRING_CONCAT = re.compile(
        r"(['\"])([^'\"\r\n]{0,4096})\1\s*\+\s*"
        r"(['\"])([^'\"\r\n]{0,4096})\3"
    )

    @property
    def name(self) -> str:
        return "JavaScriptEscape"

    def can_decode(self, data: bytes) -> bool:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return bool(self._ESCAPE.search(text) or self._FROM_CHAR_CODE.search(text))

    @staticmethod
    def _char_codes(match: re.Match[str]) -> str:
        values: list[str] = []
        for token in match.group(1).split(","):
            token = token.strip()
            try:
                value = int(token, 0)
            except ValueError:
                return match.group(0)
            if not 0 <= value <= 0x10FFFF or 0xD800 <= value <= 0xDFFF:
                return match.group(0)
            values.append(chr(value))
        return repr("".join(values)) if values else match.group(0)

    @staticmethod
    def _escape(match: re.Match[str]) -> str:
        value = match.group(1) or match.group(2) or match.group(3)
        code = int(value, 16)
        if match.group(1) and 0xD800 <= code <= 0xDFFF:
            return match.group(0)
        return chr(code)

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        if not self.can_decode(data):
            return data, False
        text = data.decode("utf-8")
        text = self._FROM_CHAR_CODE.sub(self._char_codes, text)
        text = self._ESCAPE.sub(self._escape, text)
        # Fold only adjacent static string literals. This exposes IOCs split as
        # ``fromCharCode(104,116,116,112) + '://host'`` without evaluating any
        # JavaScript expressions or identifiers.
        for _ in range(16):
            folded = self._STRING_CONCAT.sub(
                lambda match: repr(match.group(2) + match.group(4)), text
            )
            if folded == text:
                break
            text = folded
        try:
            output = text.encode("utf-8")
        except UnicodeEncodeError:
            return data, False
        return (output, True) if output != data else (data, False)


class JavaScriptEmulationDecoder(Decoder):
    """Interpret a closed, constant-only JavaScript subset to expose eval text."""

    _ASSIGNMENT = re.compile(
        r"(?is)^(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)$"
    )

    def __init__(self, max_source: int = 1024 * 1024, max_steps: int = 4096):
        self.max_source = max_source
        self.max_steps = max_steps

    @property
    def name(self) -> str:
        return "JavaScriptEmulation"

    @staticmethod
    def _statements(text: str) -> list[str]:
        statements: list[str] = []
        start = 0
        depth = 0
        quote = ""
        escaped = False
        for index, character in enumerate(text):
            if quote:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
            elif character in "'\"":
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth < 0:
                    return []
            elif character == ";" and depth == 0:
                statements.append(text[start:index].strip())
                start = index + 1
        if quote or depth:
            return []
        statements.append(text[start:].strip())
        return [statement for statement in statements if statement]

    def _decode(self, data: bytes) -> bytes | None:
        if not data or len(data) > self.max_source:
            return None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if "eval" not in text or not any(
            marker in text
            for marker in (
                "fromCharCode",
                "atob(",
                "decodeURIComponent(",
                "unescape(",
            )
        ):
            return None
        variables: dict[str, str | int] = {}
        evaluator = JavaScriptConstantEvaluator(
            max_steps=self.max_steps, max_output=self.max_source
        )
        try:
            for statement in self._statements(text)[:64]:
                assignment = self._ASSIGNMENT.fullmatch(statement)
                if assignment:
                    variables[assignment.group(1)] = evaluator.evaluate(
                        assignment.group(2), variables
                    )
                    continue
                if statement.startswith("eval(") and statement.endswith(")"):
                    value = evaluator.evaluate(statement[5:-1], variables)
                    if isinstance(value, str) and value:
                        return value.encode("utf-8")
        except (ValueError, UnicodeError):
            return None
        return None

    def can_decode(self, data: bytes) -> bool:
        return self._decode(data) is not None

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        output = self._decode(data)
        return (
            (output, True) if output is not None and output != data else (data, False)
        )


class Base58Decoder(Decoder):
    """Decode Base58 only when explicitly labeled or strongly recognizable."""

    _ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    _TABLE = {value: index for index, value in enumerate(_ALPHABET)}

    @property
    def name(self) -> str:
        return "Base58"

    def _candidate(self, data: bytes) -> tuple[bytes, bool] | None:
        value = b"".join(data.strip().split())
        explicit = value.lower().startswith(b"base58:")
        if explicit:
            value = value[7:]
        if len(value) < 8 or any(byte not in self._TABLE for byte in value):
            return None
        return value, explicit

    def _decode(self, data: bytes) -> tuple[bytes, bool] | None:
        candidate = self._candidate(data)
        if candidate is None:
            return None
        value, explicit = candidate
        number = 0
        for byte in value:
            number = number * 58 + self._TABLE[byte]
        body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
        output = b"\x00" * (len(value) - len(value.lstrip(b"1"))) + body
        if not output or (not explicit and not _meaningful_output(output)):
            return None
        return output, explicit

    def can_decode(self, data: bytes) -> bool:
        return self._decode(data) is not None

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        result = self._decode(data)
        if result is None:
            return data, False
        output, _ = result
        return (output, True) if output != data else (data, False)


class Base91Decoder(Decoder):
    """Decode Base91 with the same strict acceptance policy as Base58."""

    _ALPHABET = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        '!#$%&()*+,./:;<=>?@[]^_`{|}~"'
    )
    _TABLE = {value: index for index, value in enumerate(_ALPHABET)}

    @property
    def name(self) -> str:
        return "Base91"

    def _decode(self, data: bytes) -> bytes | None:
        try:
            text = "".join(data.decode("ascii").split())
        except UnicodeDecodeError:
            return None
        explicit = text.lower().startswith("base91:")
        if explicit:
            text = text[7:]
        if len(text) < 8 or any(char not in self._TABLE for char in text):
            return None
        value = -1
        bits = 0
        bit_count = 0
        output = bytearray()
        for char in text:
            decoded = self._TABLE[char]
            if value < 0:
                value = decoded
                continue
            value += decoded * 91
            bits |= value << bit_count
            bit_count += 13 if (value & 8191) > 88 else 14
            while bit_count >= 8:
                output.append(bits & 0xFF)
                bits >>= 8
                bit_count -= 8
            value = -1
        if value >= 0:
            output.append((bits | value << bit_count) & 0xFF)
        result = bytes(output)
        return result if result and (explicit or _meaningful_output(result)) else None

    def can_decode(self, data: bytes) -> bool:
        return self._decode(data) is not None

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        output = self._decode(data)
        return (output, True) if output and output != data else (data, False)


class BrotliDecoder(Decoder):
    """Optional bounded Brotli decoder for explicitly labeled streams."""

    def __init__(self, max_output: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output = max(1, int(max_output))

    @property
    def name(self) -> str:
        return "Brotli"

    @staticmethod
    def _candidate(data: bytes) -> bytes | None:
        # Only discard whitespace before the textual transport label.  The
        # bytes after ``brotli:`` are an opaque binary stream, so stripping
        # them can remove a legitimate final compressed byte.
        value = data.lstrip()
        if not value.lower().startswith(b"brotli:"):
            return None
        payload = value[7:]
        return payload if payload else None

    def _decode(self, data: bytes) -> bytes | None:
        value = self._candidate(data)
        if value is None:
            return None
        try:
            import brotli  # type: ignore[import-not-found]

            decoder = brotli.Decompressor()
            output = bytearray()
            for offset in range(0, len(value), 64 * 1024):
                output.extend(decoder.process(value[offset : offset + 64 * 1024]))
                if len(output) > self.max_output:
                    return None
            # brotli.Decompressor.process() can return partial output without
            # raising when the input ends before the stream does.  Never
            # report that partial evidence as a successful decode.
            if not decoder.is_finished():
                return None
            return bytes(output) if output else None
        except Exception:
            return None

    def can_decode(self, data: bytes) -> bool:
        # Recognition is deliberately independent of the optional runtime
        # dependency.  The explicit ``brotli:`` transport label is the format
        # signal; ``decode`` still fails closed when the module is unavailable
        # or the framed bytes are malformed.
        return self._candidate(data) is not None

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        output = self._decode(data)
        return (output, True) if output and output != data else (data, False)


class ZstandardDecoder(Decoder):
    """Optional streaming Zstandard decoder with an output ceiling."""

    _MAGIC = b"\x28\xb5\x2f\xfd"

    def __init__(self, max_output: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output = max(1, int(max_output))

    @property
    def name(self) -> str:
        return "Zstandard"

    def can_decode(self, data: bytes) -> bool:
        return data.startswith(self._MAGIC)

    def decode(self, data: bytes) -> tuple[bytes, bool]:
        if not self.can_decode(data):
            return data, False
        try:
            import zstandard  # type: ignore[import-not-found]

            with zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
                output = reader.read(self.max_output + 1)
            if not output or len(output) > self.max_output:
                return data, False
            return output, True
        except Exception:
            return data, False
