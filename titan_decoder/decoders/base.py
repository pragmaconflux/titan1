from abc import ABC, abstractmethod
from typing import List, Tuple
import base64
import bz2
import lzma
import zlib
import binascii
import re

from ..utils.helpers import (
    entropy,
    looks_like_base64,
    looks_like_gzip,
    looks_like_bz2,
    looks_like_hex,
    looks_like_text,
)


# Cap on decompressed output to defend against decompression bombs: a few KB of
# bz2/gzip/lzma can expand to many GB. This mirrors the size limits the archive
# (ZIP/TAR) analyzers already enforce. The engine overrides this per-decoder
# from config (max_data_size).
DEFAULT_MAX_DECOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB


def _bounded_decompress(make_decompressor, data: bytes, max_output: int) -> bytes:
    """Decompress with an output cap to defend against decompression bombs.

    ``make_decompressor`` is a zero-arg factory returning a fresh incremental
    decompressor (zlib/bz2/lzma style) exposing ``decompress(data, max_length)``,
    ``.eof`` and ``.unused_data``. Concatenated streams (e.g. multi-member gzip)
    are handled by creating a new decompressor per stream. ``decompress`` returns
    at most ``max_length`` bytes and buffers the rest, so peak memory stays
    bounded. Raises ValueError if the total output would exceed ``max_output``,
    or if the *first* stream is invalid/truncated. Trailing bytes after at least
    one complete stream (zero padding, appended payloads — both common in
    real-world samples) are tolerated: everything decoded so far is returned
    instead of discarding a valid decode because of what follows it.
    """
    result = bytearray()
    remaining = data
    first_stream = True
    while remaining:
        decompressor = make_decompressor()
        # Allow one byte past the remaining budget so overflow is detectable.
        budget = max_output - len(result) + 1
        try:
            chunk = decompressor.decompress(remaining, budget)
        except Exception:
            if first_stream:
                raise
            break  # trailing garbage after a complete stream
        if len(result) + len(chunk) > max_output:
            raise ValueError("decompressed output exceeds maximum allowed size")
        if not decompressor.eof:
            if first_stream:
                raise ValueError("truncated or incomplete compressed stream")
            # Trailing bytes happened to look like a stream start but never
            # completed: drop the partial chunk, keep the finished streams.
            break
        result += chunk
        remaining = decompressor.unused_data
        first_stream = False
    return bytes(result)


class Decoder(ABC):
    """Base class for all decoders."""

    #: Off-by-default decoders (UUEncode, ASN.1, quoted-printable, Base32) are
    #: switched on mid-run by smart detection and reset afterwards. Declaring
    #: the flag here keeps that contract on the interface instead of leaving
    #: the engine to set an attribute the base class never mentions.
    enabled: bool = True

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


def _wrapped_base64_candidate(data: bytes) -> bytes | None:
    """Return padded Base64 from a common one-character wrapper.

    Forensic payloads are frequently copied as ``<...>`` or ``[...]`` and may
    omit RFC 4648 padding. A long ``<BASE64`` prefix is also accepted because
    truncated challenge/export formats sometimes lose the closing delimiter.
    The explicit delimiter keeps this relaxed path narrow enough that ordinary
    prose is not treated as Base64.
    """
    compact = b"".join(data.split())
    if len(compact) < 18:
        return None
    wrappers = {b"<": b">", b"[": b"]", b"(": b")", b"{": b"}"}
    if wrappers.get(compact[:1]) == compact[-1:]:
        inner = compact[1:-1]
    elif compact.startswith(b"<") and len(compact) >= 82:
        inner = compact[1:]
    else:
        return None
    if len(inner) < 16 or len(inner) % 4 == 1:
        return None
    if re.fullmatch(rb"[A-Za-z0-9+/]*={0,2}", inner) is None:
        return None
    padded = inner + (b"=" * (-len(inner) % 4))
    try:
        base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return padded


class Base64Decoder(Decoder):
    """Base64 decoder with multiline support."""

    def can_decode(self, data: bytes) -> bool:
        return looks_like_base64(data) or _wrapped_base64_candidate(data) is not None

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            # Treat the input as a single base64 stream. ``b64decode`` ignores
            # embedded whitespace/newlines, so line-wrapped payloads (PEM/MIME/
            # PowerShell ``-enc``) are reconstructed byte-for-byte. Two earlier
            # bugs lived here: ``line.encode()`` on the ``bytes`` lines raised
            # AttributeError and made the decoder always fail, and joining the
            # per-line decodes with ``b"\n"`` injected spurious newlines that
            # corrupted wrapped binary payloads.
            stripped = b"".join(data.split())
            candidate = (
                stripped
                if looks_like_base64(stripped)
                else _wrapped_base64_candidate(stripped)
            )
            if candidate is None:
                return data, False
            return base64.b64decode(candidate), True
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


class Base64UrlDecoder(Decoder):
    """URL-safe base64 (RFC 4648 section 5): '-' and '_' replace '+' and '/'.

    Used by JWTs and web-based C2. It only fires when the data actually contains
    '-' or '_' -- standard base64 (which never contains those) is left to the
    Base64/RecursiveBase64 decoders, so the two never compete.
    """

    _RE = re.compile(rb"^[A-Za-z0-9_-]+={0,2}$")

    def can_decode(self, data: bytes) -> bool:
        s = data.strip()
        if len(s) < 16:
            return False
        if b"-" not in s and b"_" not in s:
            return False  # plain base64 -> handled by the standard decoders
        if not self._RE.match(s):
            return False
        try:
            base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))
            return True
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            s = data.strip()
            out = base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))
            if out and out != data:
                return out, True
            return data, False
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Base64URL"


class PemArmorDecoder(Decoder):
    """Decode PEM / ``certutil``-armored base64 bodies.

    ``certutil -encode`` and PEM wrap base64 between ``-----BEGIN X-----`` and
    ``-----END X-----`` lines. Malware smuggles executables/scripts inside fake
    "CERTIFICATE" blocks and unpacks them with ``certutil -decode``; the armor
    lines and dashes stop the plain base64 detector from firing. Extract the
    body of each block and base64-decode it (concatenating multiple blocks).
    """

    _BLOCK = re.compile(
        rb"-----BEGIN [^-\r\n]*-----(.*?)-----END [^-\r\n]*-----",
        re.DOTALL,
    )

    def can_decode(self, data: bytes) -> bool:
        if b"-----BEGIN " not in data or b"-----END " not in data:
            return False
        return self._BLOCK.search(data) is not None

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            out = bytearray()
            for match in self._BLOCK.finditer(data):
                body = b"".join(match.group(1).split())  # strip line wrapping
                if not body:
                    continue
                try:
                    out += base64.b64decode(body + b"=" * (-len(body) % 4))
                except Exception:
                    continue
            if out:
                return bytes(out), True
            return data, False
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "PEM"


class GzipDecoder(Decoder):
    """Gzip decompressor."""

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        return looks_like_gzip(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            # wbits=31 selects the gzip header/format.
            return _bounded_decompress(
                lambda: zlib.decompressobj(31), data, self.max_output_size
            ), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Gzip"


class Bz2Decoder(Decoder):
    """Bz2 decompressor."""

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        return looks_like_bz2(data)

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            return _bounded_decompress(
                bz2.BZ2Decompressor, data, self.max_output_size
            ), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "Bz2"


class LzmaDecoder(Decoder):
    """LZMA/XZ decompressor."""

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        return data.startswith(b"\xfd7zXZ") or data.startswith(b"\x5d\x00\x00")

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            return _bounded_decompress(
                lzma.LZMADecompressor, data, self.max_output_size
            ), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "LZMA"


class ZlibDecoder(Decoder):
    """ZLIB decompressor."""

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        # Validate the full RFC 1950 header instead of only the low nibble of
        # the first byte: that alone matched ~6% of random binary data and
        # triggered a doomed decompression attempt on every such node.
        if len(data) < 2:
            return False
        cmf, flg = data[0], data[1]
        if cmf & 0x0F != 8:  # CM: 8 = deflate
            return False
        if cmf >> 4 > 7:  # CINFO: window size may not exceed 32KB
            return False
        # FCHECK: header bytes as a big-endian value must be divisible by 31.
        return ((cmf << 8) | flg) % 31 == 0

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            return _bounded_decompress(
                zlib.decompressobj, data, self.max_output_size
            ), True
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


# Relative frequencies (percent) of letters in English text. Used to decide
# whether a ROT13 rotation actually yields more English-like output than its
# input, so the self-inverse cipher is not applied to already-readable text.
_ENGLISH_LETTER_FREQ = {
    "a": 8.2,
    "b": 1.5,
    "c": 2.8,
    "d": 4.3,
    "e": 12.7,
    "f": 2.2,
    "g": 2.0,
    "h": 6.1,
    "i": 7.0,
    "j": 0.15,
    "k": 0.77,
    "l": 4.0,
    "m": 2.4,
    "n": 6.7,
    "o": 7.5,
    "p": 1.9,
    "q": 0.095,
    "r": 6.0,
    "s": 6.3,
    "t": 9.1,
    "u": 2.8,
    "v": 0.98,
    "w": 2.4,
    "x": 0.15,
    "y": 2.0,
    "z": 0.074,
}


def _english_likeness(text: str) -> float:
    """Average English letter frequency over the alphabetic characters in text.

    Higher means more English-like. ROT13 ciphertext of English scores low;
    actual English prose scores high. Returns 0.0 when there are no letters.
    """
    letters = [c.lower() for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(_ENGLISH_LETTER_FREQ.get(c, 0.0) for c in letters) / len(letters)


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
        if _wrapped_base64_candidate(data) is not None:
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

            # ROT13 is self-inverse, so it cannot tell plaintext from ciphertext
            # by structure alone. Only treat it as a successful decode when the
            # rotation makes the text more English-like; otherwise we would mangle
            # already-readable content into garbage and pollute downstream IOCs.
            if _english_likeness(decoded) <= _english_likeness(text):
                return data, False

            return decoded.encode("ascii"), True
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "ROT13"


def _build_xor_score_table() -> list:
    """Per-byte text-likeness weights for scoring single-byte-XOR candidates."""
    table = [-1.5] * 256  # non-printable bytes: strong penalty
    for i in range(32, 127):
        table[i] = 0.1  # other printable ASCII
    for i in range(0x30, 0x3A):
        table[i] = 0.4  # digits
    for i in range(0x41, 0x5B):
        table[i] = 0.6  # uppercase
    for i in range(0x61, 0x7B):
        table[i] = 1.0  # lowercase
    for ch in b"./:@-_?=&%+":
        table[ch] = 0.4  # URL / path punctuation
    table[0x20] = 1.0  # space (strong text signal)
    for ch in (0x09, 0x0A, 0x0D):
        table[ch] = 0.3  # tab / newlines
    return table


_XOR_SCORE = _build_xor_score_table()


def _xor_text_likeness(data: bytes) -> float:
    """Higher => more like readable text/commands/URLs. Range roughly [-1.5, 1.0]."""
    if not data:
        return -1.0
    return sum(_XOR_SCORE[b] for b in data) / len(data)


def _best_key_over_hist(hist: list) -> tuple:
    """Return ``(best_key, best_total)`` maximizing text-likeness over a byte
    histogram.

    Each XOR column (and the single-byte case over the whole sample) is a
    single-byte XOR, so the best key is found by scoring all 256 keys against
    the histogram of present byte values — cost bounded by the number of
    distinct bytes, independent of input length.
    """
    table = _XOR_SCORE
    present = [(b, c) for b, c in enumerate(hist) if c]
    best_key = 0
    best_score = float("-inf")
    for key in range(256):
        s = 0.0
        for b, c in present:
            s += table[b ^ key] * c
        if s > best_score:
            best_score = s
            best_key = key
    return best_key, best_score


def _histogram(data: bytes) -> list:
    hist = [0] * 256
    for b in data:
        hist[b] += 1
    return hist


def _best_column_key(column: bytes) -> int:
    if not column:
        return 0
    return _best_key_over_hist(_histogram(column))[0]


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if len(key) == 1:
        return data.translate(bytes(i ^ key[0] for i in range(256)))
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))


class XorDecoder(Decoder):
    """XOR decoder: single-byte and repeating-key (key lengths 1--8).

    Single-byte keys are recovered by a 256-key brute force. Repeating keys are
    recovered per key length by a column-wise frequency analysis: for each
    candidate length L, every L-th byte forms a column that is itself a
    single-byte XOR, so the best key byte for each column is found independently
    and the columns are reassembled into the full key. This recovers, e.g., a
    4KB config XOR'd with a 4-byte key that single-byte analysis cannot touch.

    Cost stays bounded by a **sampling** strategy: all candidate keys are scored
    on a bounded prefix sample, and the full input is only decoded once, for the
    single accepted key. This lets the size cap rise well above the old 512-byte
    limit without an unbounded brute force.

    Accepts only a clearly text-like reveal that beats reading the bytes as-is,
    with a stricter margin for longer keys (which have more freedom to overfit
    noise), so it does not scramble already-readable, random, hex, or base64
    data.
    """

    # Upper bound on input size XOR will attempt. Scoring is sampled, and the
    # single full decode on acceptance is a linear pass, so this can be large.
    MAX_SIZE = 1024 * 1024
    # Bytes of the input used to score candidate keys.
    SAMPLE_SIZE = 4096
    MAX_KEY_LEN = 8

    def can_decode(self, data: bytes) -> bool:
        n = len(data)
        if n < 8 or n > self.MAX_SIZE:
            return False
        if len(set(data)) < 8:  # near-uniform / padding is not XOR'd text
            return False
        # hex/base64 have dedicated decoders; don't XOR-scramble them.
        if looks_like_hex(data) or looks_like_base64(data):
            return False
        # XOR is a bijection, so XOR'd *text* keeps text-level entropy (~4-5).
        # Near-random input (entropy ~8, e.g. compressed/encrypted/random data)
        # cannot be XOR'd text; skip it. This also keeps the (bounded but
        # non-trivial) column analysis off the many high-entropy binary nodes
        # the engine sees.
        if entropy(data[: self.SAMPLE_SIZE]) > 6.5:
            return False
        return True

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        sample = data[: self.SAMPLE_SIZE]
        raw = _xor_text_likeness(sample)
        slen = len(sample)

        # ``best_selection`` includes a per-length penalty so a longer key must
        # be meaningfully better to win; ``best_true`` is the unpenalized
        # text-likeness used for the acceptance gate.
        best_selection = raw
        best_true = raw
        best_key: bytes | None = None

        # Single-byte (length 1): scored over the sample histogram, no penalty.
        sb_key, sb_total = _best_key_over_hist(_histogram(sample))
        sb_score = sb_total / slen if slen else raw
        if sb_key != 0 and sb_score > best_selection:
            best_selection = sb_score
            best_true = sb_score
            best_key = bytes([sb_key])

        # Repeating keys (lengths 2..8) via per-column frequency analysis.
        for klen in range(2, self.MAX_KEY_LEN + 1):
            if len(sample) < klen * 4:  # too little data to trust the recovery
                continue
            key = bytes(_best_column_key(sample[col::klen]) for col in range(klen))
            if all(k == 0 for k in key):
                continue
            score = _xor_text_likeness(_xor_bytes(sample, key))
            selection = score - self._length_penalty(klen)
            if selection > best_selection:
                best_selection = selection
                best_true = score
                best_key = key

        if best_key is None:
            return data, False

        # Acceptance gate on the sample's true text-likeness.
        if not (
            best_true >= 0.70
            and best_true >= raw + 0.20
            and looks_like_text(_xor_bytes(sample, best_key))
        ):
            return data, False

        # Accepted: decode the full input once with the chosen key.
        full = _xor_bytes(data, best_key)
        if looks_like_text(full[: self.SAMPLE_SIZE]):
            return full, True
        return data, False

    @staticmethod
    def _length_penalty(klen: int) -> float:
        # Longer keys need a cleaner reveal to be accepted.
        return 0.03 * (klen - 1)

    @property
    def name(self) -> str:
        return "XOR"


class PDFDecoder(Decoder):
    """Object-graph-aware PDF decoder.

    Parses the PDF into an object table (via
    :class:`titan_decoder.decoders.pdf.PDFDocument`), decompresses object
    streams (``/Type /ObjStm``) so their packed objects become visible,
    resolves indirect references, and applies ``/Filter`` chains
    (FlateDecode/ASCIIHexDecode/ASCII85Decode/LZWDecode, with predictors).

    It then extracts the security-relevant parts by reference rather than by
    regex: decoded stream bodies, ``/JS`` / ``/JavaScript`` action code,
    ``/OpenAction`` targets, and ``/EmbeddedFile`` contents. This resolves a
    stream referenced only as ``5 0 R`` and recovers objects packed inside an
    object stream — neither of which the old regex/window approach could see.
    """

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        """Check if data looks like a PDF file."""
        return data.startswith(b"%PDF-") and b"%%EOF" in data

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        """Parse the PDF object graph and extract decoded/decoded-by-ref content."""
        from .pdf import PDFDocument, PDFStream

        try:
            doc = PDFDocument(data, max_output=self.max_output_size)
        except Exception:
            return data, False

        try:
            parts: List[bytes] = []
            total = 0

            def add(chunk: bytes) -> bool:
                nonlocal total
                if not chunk:
                    return True
                room = self.max_output_size - total
                if room <= 0:
                    return False
                if len(chunk) > room:
                    chunk = chunk[:room]
                parts.append(chunk)
                total += len(chunk)
                return True

            # 1. Decode every stream body (bounded), labeled by object id.
            for (num, gen), obj in sorted(doc.objects.items()):
                if total >= self.max_output_size:
                    break
                if not isinstance(obj, PDFStream):
                    continue
                try:
                    decoded = doc.decode_stream(obj)
                except Exception:
                    decoded = obj.raw
                if decoded:
                    if not add(f"=== obj {num} {gen} stream ===\n".encode()):
                        break
                    if not add(decoded):
                        break

            # 2. Extract JavaScript, OpenAction, and embedded files by reference.
            self._extract_actions(doc, add)

            if parts:
                # Cap the joined result too (join separators add bytes past the
                # per-chunk accounting).
                return b"\n".join(parts)[: self.max_output_size], True
            return data, False
        except Exception:
            return data, False

    def _extract_actions(self, doc, add) -> None:
        from .pdf import PDFName, PDFStream

        def to_bytes(val) -> bytes:
            val = doc.resolve(val)
            if isinstance(val, bytes):
                return val
            if isinstance(val, PDFStream):
                try:
                    return doc.decode_stream(val)
                except Exception:
                    return val.raw
            if isinstance(val, PDFName):
                return val.value.encode("latin-1", "replace")
            if isinstance(val, str):
                return val.encode("utf-8", "replace")
            return b""

        for key, obj in sorted(doc.objects.items()):
            d = obj.dict if isinstance(obj, PDFStream) else obj
            if not isinstance(d, dict):
                continue
            # JavaScript actions: /JS may be a string or an indirect stream ref.
            if "JS" in d:
                js = to_bytes(d.get("JS"))
                if js:
                    add(b"=== /JS action ===\n")
                    add(js)
            if "JavaScript" in d:
                js = to_bytes(d.get("JavaScript"))
                if js:
                    add(b"=== /JavaScript ===\n")
                    add(js)
            # OpenAction: auto-run on document open.
            if "OpenAction" in d:
                oa = doc.resolve(d.get("OpenAction"))
                if isinstance(oa, dict) and "JS" in oa:
                    js = to_bytes(oa.get("JS"))
                    if js:
                        add(b"=== /OpenAction /JS ===\n")
                        add(js)
            # Embedded files: /EF -> /F -> file stream.
            if "EF" in d:
                ef = doc.resolve(d.get("EF"))
                if isinstance(ef, dict):
                    for fk in ("F", "UF", "DOS", "Mac", "Unix"):
                        if fk in ef:
                            content = to_bytes(ef.get(fk))
                            if content:
                                add(b"=== /EmbeddedFile ===\n")
                                add(content)
                                break

    @property
    def name(self) -> str:
        return "PDF"


class OLEDecoder(Decoder):
    """Compound File Binary (OLE2) decoder.

    Walks the real CFB structure (header, FAT/DIFAT, directory tree, mini
    stream) via :class:`titan_decoder.decoders.cfb.CFBReader`, enumerates
    streams by their directory path, and decompresses VBA source from module
    streams using the [MS-OVBA] container format. Extracted artifacts are
    labeled with their real stream path (e.g. ``Macros/VBA/Module1``) rather
    than a byte window carved around a magic string, which eliminated the old
    carver's false positives (signature bytes appearing in random stream data).

    Output is a small text index of stream paths/sizes followed by the stream
    bodies, all bounded by ``max_output_size`` so a crafted file with many or
    huge streams cannot amplify without limit.
    """

    def __init__(self, max_output_size: int = DEFAULT_MAX_DECOMPRESSED_SIZE):
        self.max_output_size = max_output_size

    def can_decode(self, data: bytes) -> bool:
        """Check if data looks like a CFB/OLE2 file."""
        if len(data) < 512:
            return False
        # CFB signature: D0 CF 11 E0 A1 B1 1A E1
        return data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        """Parse the CFB structure and extract real streams + VBA source."""
        from .cfb import CFBReader, is_vba_module_stream, CFBError

        try:
            reader = CFBReader(data, max_total_bytes=self.max_output_size)
        except CFBError:
            return data, False
        except Exception:
            return data, False

        try:
            parts: List[bytes] = []
            total = 0

            for path, entry in reader.streams():
                if total >= self.max_output_size:
                    break
                try:
                    stream = reader.read_stream(entry)
                except Exception:
                    continue
                if not stream:
                    continue

                emitted = stream
                label = path
                # VBA module streams hold their source as an MS-OVBA compressed
                # container. Recover the decompressed source so downstream IOC
                # extraction sees the actual macro text, not the packed bytes.
                if is_vba_module_stream(path):
                    src = self._decompress_module(stream)
                    if src:
                        emitted = src
                        label = f"{path} (decompressed VBA)"

                room = self.max_output_size - total
                if room <= 0:
                    break
                header = f"=== stream: {label} ({len(emitted)} bytes) ===\n".encode(
                    "utf-8", errors="replace"
                )
                chunk = header + emitted
                if len(chunk) > room:
                    chunk = chunk[:room]
                parts.append(chunk)
                total += len(chunk)

            if parts:
                return b"\n".join(parts), True
            return data, False
        except Exception:
            return data, False

    def _decompress_module(self, stream: bytes) -> bytes:
        """Recover VBA source from a module stream.

        A module stream stores the compressed source at an offset given in the
        project ``dir`` stream. Rather than fully parse ``dir``, locate the
        MS-OVBA container by its ``0x01`` signature byte and try decompressing
        from each candidate offset, returning the largest well-formed,
        text-like result. This is bounded to a handful of candidates.
        """
        from .cfb import decompress_ovba, CFBError

        best = b""
        candidates = 0
        pos = 0
        while candidates < 32:
            idx = stream.find(b"\x01", pos)
            if idx == -1:
                break
            pos = idx + 1
            candidates += 1
            try:
                out = decompress_ovba(stream[idx:], max_output=self.max_output_size)
            except CFBError:
                continue
            except Exception:
                continue
            # Accept only a substantial, mostly-printable result (VBA source is
            # ASCII text); this rejects false 0x01 offsets in binary padding.
            if len(out) > len(best) and self._looks_like_source(out):
                best = out
        return best

    @staticmethod
    def _looks_like_source(data: bytes) -> bool:
        if len(data) < 8:
            return False
        printable = sum(1 for b in data[:4096] if 9 <= b <= 13 or 32 <= b <= 126)
        return printable >= 0.80 * min(len(data), 4096)

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
        # Implemented with binascii.a2b_uu rather than the stdlib `uu` module,
        # which is deprecated (3.11) and removed in Python 3.13.
        try:
            out = bytearray()
            started = False
            for raw in data.split(b"\n"):
                line = raw.rstrip(b"\r")
                if not started:
                    if line.startswith(b"begin "):
                        started = True
                    continue
                if line.startswith(b"end"):
                    break
                if not line or line == b"`":
                    # ` is the zero-length data line that precedes `end`.
                    continue
                try:
                    out += binascii.a2b_uu(line)
                except binascii.Error:
                    # Some encoders strip trailing whitespace; recompute the
                    # expected line length (length char + data chars, same
                    # formula as CPython's uu module) and retry on that slice.
                    try:
                        nchars = (((line[0] - 32) & 0x3F) * 4 + 5) // 3
                        out += binascii.a2b_uu(line[:nchars])
                    except binascii.Error:
                        # Truly corrupt line. Skip it and keep decoding:
                        # aborting here used to discard every line already
                        # recovered, so one flipped byte mid-file lost the
                        # whole artifact. Best-effort recovery of the
                        # remaining lines is what triage needs.
                        continue

            decoded = bytes(out)
            if decoded:
                return decoded, True
            return data, False
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

            # Constructed types (SEQUENCE 0x30, SET 0x31, constructed context
            # tags) all set bit 0x20. Almost all real ASN.1 wraps its content in
            # an outer SEQUENCE, so we must descend into them; previously this
            # method never recursed (the depth parameter was dead), so anything
            # below the top level — i.e. every realistic cert/key — extracted
            # nothing.
            if tag & 0x20:
                nested = self._parse_asn1(value, depth + 1)
                if nested:
                    result.append(nested)
            elif tag == 0x04:  # OCTET STRING
                result.append(value)
            elif tag == 0x0C:  # UTF8String
                result.append(value)
            elif tag == 0x13:  # PrintableString
                result.append(value)

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
            return bool(re.search(r"=[0-9A-F]{2}", text, re.IGNORECASE))
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            import quopri

            decoded = quopri.decodestring(data)
            if decoded != data:
                return decoded, True
            return data, False
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
            # Padded input is a multiple of 8; with padding stripped the only
            # lengths base32 can produce are 2/4/5/7 (mod 8). The old check
            # only allowed 0 and 7, rejecting valid unpadded input.
            if len(text) % 8 not in (0, 2, 4, 5, 7):
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
    """URL percent-encoding decoder.

    Percent-encoding is a text transport, so this only fires on valid UTF-8
    input. Decoding with ``errors="ignore"`` on binary data silently deleted
    every non-UTF-8 byte and the mangled output still compared unequal to the
    input, so the "decode" was reported successful — and the byte destruction
    looked like entropy reduction, letting this decoder outscore the correct
    one (e.g. Gzip on a gzip stream that happens to contain ``%XX``) and kill
    the real decode chain. The same fix applies to HTMLEntityDecoder and
    UnicodeEscapeDecoder below.
    """

    def can_decode(self, data: bytes) -> bool:
        if not looks_like_text(data):
            return False
        try:
            text = data.decode("utf-8")
            return bool(re.search(r"%[0-9A-Fa-f]{2}", text))
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("utf-8")
            # '+' means space only in the application/x-www-form-urlencoded
            # context: a URL's query component, or a bare form-encoded body.
            # Converting it everywhere corrupted '+' that is literal data --
            # most damagingly base64 embedded in percent-encoded payloads,
            # where each converted '+' broke the next decode layer. Convert
            # only past the first '?', or throughout a bare k=v&k=v body
            # ('&' never occurs in base64, so that shape is a safe signal).
            qpos = text.find("?")
            plus_from: int | None
            if qpos != -1:
                plus_from = qpos
            elif "=" in text and "&" in text:
                plus_from = -1
            else:
                plus_from = None
            # Use a bytearray: byte concatenation in a loop (result += ...) is
            # O(n^2) and hangs on percent-heavy payloads.
            result = bytearray()
            n = len(text)
            i = 0
            while i < n:
                ch = text[i]
                if ch == "%" and i + 2 < n:
                    try:
                        result.append(int(text[i + 1 : i + 3], 16))
                        i += 3
                        continue
                    except ValueError:
                        pass
                if ch == "+" and plus_from is not None and i > plus_from:
                    result += b" "
                else:
                    result += ch.encode("utf-8")
                i += 1
            out = bytes(result)
            return (out if out else data), bool(out and out != data)
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "URLDecoder"


class HTMLEntityDecoder(Decoder):
    """HTML entity decoder (text-only; see URLDecoder docstring)."""

    def can_decode(self, data: bytes) -> bool:
        if not looks_like_text(data):
            return False
        try:
            text = data.decode("utf-8")
            return bool(
                re.search(r"&#(?:\d+|x[0-9A-Fa-f]+);|&[a-z]+;", text, re.IGNORECASE)
            )
        except Exception:
            return False

    _ENTITY_RE = re.compile(r"&#(\d+);|&#x([0-9A-Fa-f]+);|&([a-zA-Z]+);")
    _NAMED = {
        # nbsp is U+00A0, but it is deliberately normalized to a plain space:
        # downstream IOC regexes rely on ASCII word boundaries.
        "nbsp": 0x20,
        "lt": ord("<"),
        "gt": ord(">"),
        "amp": ord("&"),
        "quot": ord('"'),
        "apos": ord("'"),
    }

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("utf-8")

            # Single-pass substitution: the previous char-by-char scan sliced
            # text[i:] and re-ran the regex for every character (O(n^2)), which
            # hangs on entity-heavy payloads.
            def _sub(m: "re.Match") -> str:
                # Numeric entities in the UTF-16 surrogate range (U+D800..DFFF)
                # are kept literal: chr() accepts them but the resulting lone
                # surrogate cannot be UTF-8-encoded, so one crafted entity
                # (e.g. &#55296;) would make encode() raise and void the whole
                # decode. Same handling as UnicodeEscapeDecoder.
                dec, hexv, name = m.group(1), m.group(2), m.group(3)
                if dec is not None:
                    try:
                        code = int(dec)
                        if 0xD800 <= code <= 0xDFFF:
                            return m.group(0)
                        return chr(code)
                    except (ValueError, OverflowError):
                        return m.group(0)
                if hexv is not None:
                    try:
                        code = int(hexv, 16)
                        if 0xD800 <= code <= 0xDFFF:
                            return m.group(0)
                        return chr(code)
                    except (ValueError, OverflowError):
                        return m.group(0)
                named = self._NAMED.get(name.lower())
                return chr(named) if named is not None else m.group(0)

            decoded = self._ENTITY_RE.sub(_sub, text).encode("utf-8")
            return decoded, decoded != data
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "HTMLEntity"


class UnicodeEscapeDecoder(Decoder):
    """Unicode escape sequences decoder (text-only; see URLDecoder docstring)."""

    def can_decode(self, data: bytes) -> bool:
        if not looks_like_text(data):
            return False
        try:
            text = data.decode("utf-8")
            return bool(re.search(r"\\u[0-9A-Fa-f]{4}|\\U[0-9A-Fa-f]{8}", text))
        except Exception:
            return False

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            text = data.decode("utf-8")
            result = []
            i = 0

            while i < len(text):
                # Try \\UXXXXXXXX
                if text[i : i + 2] == "\\U" and i + 10 <= len(text):
                    try:
                        code = int(text[i + 2 : i + 10], 16)
                        if not 0xD800 <= code <= 0xDFFF:  # lone surrogate: literal
                            result.append(chr(code))
                            i += 10
                            continue
                    except (ValueError, OverflowError):
                        pass

                # Try \\uXXXX
                if text[i : i + 2] == "\\u" and i + 6 <= len(text):
                    try:
                        code = int(text[i + 2 : i + 6], 16)
                        if 0xD800 <= code <= 0xDBFF and text[i + 6 : i + 8] == "\\u":
                            # Surrogate pair (the standard JSON escape form for
                            # astral chars, e.g. 😀). Unpaired
                            # surrogates can't be UTF-8-encoded — previously
                            # they made encode() raise and the whole decode
                            # fail via the blanket except.
                            low = int(text[i + 8 : i + 12], 16)
                            if 0xDC00 <= low <= 0xDFFF:
                                combined = (
                                    0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                                )
                                result.append(chr(combined))
                                i += 12
                                continue
                        elif not 0xD800 <= code <= 0xDFFF:
                            result.append(chr(code))
                            i += 6
                            continue
                        # Lone surrogate: fall through, keep the escape literal.
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


class Utf16Decoder(Decoder):
    """Decode UTF-16 text to UTF-8.

    Real-world malware constantly carries UTF-16LE text -- most notably
    PowerShell ``-EncodedCommand`` (UTF-16LE then base64) and .NET string blobs.
    After the base64 layer is peeled the bytes are UTF-16, which the engine's
    UTF-8 preview reads as e.g. ``h\\x00t\\x00t\\x00p...``; the interleaved NUL
    bytes then break IOC regexes. Converting UTF-16 -> UTF-8 restores clean text
    for downstream extraction.
    """

    def _endianness(self, data: bytes):
        """Return 'utf-16-le'/'utf-16-be' if data looks like UTF-16 text, else None."""
        if len(data) < 8:
            return None
        if data[:2] == b"\xff\xfe":
            return "utf-16-le"
        if data[:2] == b"\xfe\xff":
            return "utf-16-be"
        sample = data[:1024]
        if len(sample) % 2:
            sample = sample[:-1]
        pairs = len(sample) // 2
        if pairs < 4:
            return None
        odd_nul = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
        even_nul = sum(1 for i in range(0, len(sample), 2) if sample[i] == 0)
        # ASCII carried in UTF-16 puts the NUL high byte on one fixed parity and
        # (almost) never on the other. Requiring one parity ~all-NUL and the
        # other ~none excludes binary/PE null padding (NULs on both parities),
        # random data, and plain text (no NULs) -- verified 0 false positives.
        if odd_nul >= 0.6 * pairs and even_nul <= 0.05 * pairs:
            return "utf-16-le"
        if even_nul >= 0.6 * pairs and odd_nul <= 0.05 * pairs:
            return "utf-16-be"
        return None

    def can_decode(self, data: bytes) -> bool:
        return self._endianness(data) is not None

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        enc = self._endianness(data)
        if enc is None:
            return data, False
        try:
            text = data.decode(enc, errors="ignore")
            # Explicit-endian codecs do not consume a leading BOM: it decodes
            # to U+FEFF, which would re-encode as \xef\xbb\xbf at the front of
            # the UTF-8 output, corrupting the artifact and its hash.
            text = text.lstrip("\ufeff")
            out = text.encode("utf-8", errors="ignore").replace(b"\x00", b"")
            if out and out != data:
                return out, True
            return data, False
        except Exception:
            return data, False

    @property
    def name(self) -> str:
        return "UTF16"
