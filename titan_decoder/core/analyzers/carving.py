"""Carve encoded payload regions out of host files.

Titan's decoders are whole-buffer transforms: ``can_decode`` inspects the
entire input, so a payload only decodes when the artifact *is* the encoded
blob. Real samples almost always carry the blob **inside** a host — a base64
string assigned to a JavaScript variable, a hex blob in an XML attribute, a
PowerShell here-string, a registry export, a config value. For those, every
whole-buffer decoder correctly declines, and the chain stops at the host file.

This module closes that gap. It scans a host buffer for runs of encoded
alphabet characters, decodes each candidate independently, and emits the ones
that decode to something real as named child artifacts with their byte offset
recorded. The engine then recurses into them exactly as it would into an
archive member, so a carved blob re-enters the normal decoder pipeline and a
multi-layer chain (base64 inside a script, gzip inside that, a PowerShell
command inside that) unwinds on its own.

Precision, not recall, is the governing constraint. Long alphabet runs are
common in benign content — checksums, UUID tables, minified assets, embedded
certificates, base64 images — so a candidate is only emitted when it clears a
minimum length, decodes cleanly, and produces output that
``looks_meaningful_payload`` accepts. Speculative noise is dropped rather than
reported, because a fabricated artifact costs an analyst more than a missed
one costs Titan.

Carving *composes*: it runs in addition to whichever format analyzer claims
the host, never instead of it, so a script is still script-analyzed while its
embedded blob is carved out.
"""

from __future__ import annotations

import base64
import binascii
import re
import zlib
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

from ...utils.helpers import looks_meaningful_payload, sha256
from .base import Analyzer

# Container signatures that mark carved output as a real payload even though it
# is not printable. These are deliberately kept local to carving rather than
# widened into the shared decoder gate, where accepting more binary shapes
# would loosen every transport decoder's output check at the same time.
_CARVED_CONTAINER_MAGICS = (
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # OLE / CFB (Office, MSI)
    b"\x28\xb5\x2f\xfd",  # Zstandard
    b"7z\xbc\xaf\x27\x1c",  # 7-Zip
    b"\x78\x01",  # zlib, no/low compression
    b"\x78\x5e",  # zlib, fast
    b"\x78\x9c",  # zlib, default
    b"\x78\xda",  # zlib, best
)


@dataclass(frozen=True)
class CarvedPayload:
    """One decoded region recovered from a host buffer."""

    name: str
    data: bytes
    offset: int
    encoding: str


def _decode_base64(raw: bytes) -> bytes | None:
    padded = raw + b"=" * (-len(raw) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None


def _decode_base64url(raw: bytes) -> bytes | None:
    padded = raw + b"=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return None


def _looks_like_utf16_text(data: bytes) -> bool:
    """Return whether data looks like UTF-16LE/BE encoded text.

    UTF-16 payloads are roughly half NUL bytes, so the printable-ratio gate
    rejects them even though they are ordinary text. PowerShell's
    ``-EncodedCommand`` and Windows configuration blobs use this encoding
    constantly, which makes it worth recognizing explicitly.
    """
    if len(data) < 8 or len(data) % 2:
        return False
    for offset in (0, 1):
        window = data[offset : offset + 512]
        pairs = [window[index : index + 2] for index in range(0, len(window) - 1, 2)]
        if not pairs:
            continue
        nulls = sum(1 for pair in pairs if pair[1] == 0)
        if nulls / len(pairs) >= 0.85:
            try:
                data.decode("utf-16-le" if offset == 0 else "utf-16-be")
            except (UnicodeDecodeError, ValueError):
                continue
            return True
    return False


def _inflates(data: bytes, limit: int = 1 << 20) -> bool:
    """Return whether data is a headerless DEFLATE stream that decompresses.

    Raw DEFLATE and zlib carry no reliable signature, so the only sound test
    is a bounded trial decompression. Random bytes essentially never inflate,
    so this admits real compressed payloads without admitting noise.
    """
    for wbits in (-15, 15):
        try:
            out = zlib.decompressobj(wbits).decompress(data, limit)
        except zlib.error:
            continue
        if out:
            return True
    return False


def _carved_output_is_meaningful(data: bytes) -> bool:
    """Carving's acceptance gate: did this region decode to a real payload?"""
    if looks_meaningful_payload(data):
        return True
    if any(data.startswith(magic) for magic in _CARVED_CONTAINER_MAGICS):
        return True
    if _looks_like_utf16_text(data):
        return True
    return _inflates(data)


def _decode_hex(raw: bytes) -> bytes | None:
    if len(raw) % 2:
        raw = raw[:-1]
    try:
        return binascii.unhexlify(raw)
    except (binascii.Error, ValueError):
        return None


class EmbeddedPayloadAnalyzer(Analyzer):
    """Extract encoded payload regions embedded inside a host artifact."""

    # (encoding, pattern, minimum run length, decoder)
    _CANDIDATES: Tuple[Tuple[str, "re.Pattern[bytes]", int, Any], ...] = (
        ("base64", re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}"), 24, _decode_base64),
        ("base64url", re.compile(rb"[A-Za-z0-9_-]{24,}={0,2}"), 24, _decode_base64url),
        ("hex", re.compile(rb"(?:[0-9a-fA-F]{2}){16,}"), 32, _decode_hex),
    )

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}
        self.max_artifacts = int(self.config.get("max_carved_artifacts", 8))
        self.max_artifact_size = int(
            self.config.get("max_carved_artifact_size", 4 * 1024 * 1024)
        )
        self.max_total_size = int(
            self.config.get("max_carved_total_size", 16 * 1024 * 1024)
        )
        self.scan_bytes = int(self.config.get("max_carve_scan_bytes", 4 * 1024 * 1024))
        self.min_run = int(self.config.get("min_carved_run_length", 24))

    @property
    def name(self) -> str:
        return "EmbeddedPayload"

    @property
    def composes(self) -> bool:
        """Carving adds artifacts alongside the claiming format analyzer."""
        return True

    def _host_is_scannable(self, data: bytes) -> bool:
        # A run can only be carved out of a *host*: if the artifact is itself
        # (almost entirely) one encoded blob, the whole-buffer decoders already
        # own it and carving would just duplicate their work one node earlier.
        if not data or len(data) < self.min_run + 8:
            return False
        stripped = b"".join(data.split())
        if not stripped:
            return False
        for _encoding, pattern, _minimum, _decoder in self._CANDIDATES:
            match = pattern.fullmatch(stripped)
            if match is not None:
                return False
        return True

    def carve(self, data: bytes) -> List[CarvedPayload]:
        """Return decoded embedded regions, ordered by offset then encoding."""
        if not self._host_is_scannable(data):
            return []

        window = data[: self.scan_bytes]
        found: List[CarvedPayload] = []
        # Deduplicate by decoded content: the base64 and base64url alphabets
        # overlap, so an ordinary base64 run matches both patterns and would
        # otherwise be emitted twice.
        seen: set[str] = set()
        seen_spans: set[Tuple[int, int]] = set()

        for encoding, pattern, minimum, decoder in self._CANDIDATES:
            for match in pattern.finditer(window):
                raw = match.group(0)
                if len(raw) < minimum:
                    continue
                span = match.span()
                if span in seen_spans:
                    continue
                decoded = decoder(raw)
                if not decoded or len(decoded) > self.max_artifact_size:
                    continue
                if decoded == data or decoded == raw:
                    continue
                if not _carved_output_is_meaningful(decoded):
                    continue
                digest = sha256(decoded)
                if digest in seen:
                    continue
                seen.add(digest)
                seen_spans.add(span)
                offset = span[0]
                found.append(
                    CarvedPayload(
                        name=f"embedded_{encoding}_0x{offset:06x}.bin",
                        data=decoded,
                        offset=offset,
                        encoding=encoding,
                    )
                )

        # Deterministic order regardless of which pattern matched first.
        found.sort(key=lambda item: (item.offset, item.encoding))

        bounded: List[CarvedPayload] = []
        total = 0
        for payload in found:
            if len(bounded) >= self.max_artifacts:
                break
            if total + len(payload.data) > self.max_total_size:
                break
            total += len(payload.data)
            bounded.append(payload)
        return bounded

    def can_analyze(self, data: bytes) -> bool:
        return bool(self.carve(data))

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        return [(payload.name, payload.data) for payload in self.carve(data)]
