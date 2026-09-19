"""Bounded static analyzers for common delivery and container formats."""

from __future__ import annotations

from email import policy
from email.parser import BytesParser
import copy
from hashlib import sha256
import html
import io
import json
from pathlib import Path, PurePosixPath
import re
import struct
import tempfile
from typing import Any, Iterable
import zipfile

from .base import Analyzer
from ...decoders.advanced import (
    JavaScriptEscapeDecoder,
    JavaScriptEmulationDecoder,
    PowerShellEncodedCommandDecoder,
)
from ...decoders.base import UnicodeEscapeDecoder
from ...decoders.cfb import CFBError, CFBReader, CFB_SIGNATURE


def _safe_name(value: str, fallback: str = "artifact.bin") -> str:
    value = value.replace("\\", "/").rsplit("/", 1)[-1]
    value = "".join(char for char in value if char.isalnum() or char in "._- ")
    return value[:160] or fallback


def _safe_archive_path(value: str) -> PurePosixPath | None:
    """Return a normalized relative archive path or reject unsafe members."""
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or not path.parts:
        return None
    if any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path


def _bounded_summary(summary: dict[str, Any], limit: int) -> bytes | None:
    """Serialize an analyzer summary as valid JSON within ``limit`` bytes.

    Slicing the serialized form to a byte budget -- ``encoded[: max_item]`` --
    cuts mid-token and emits an unparseable artifact, silently, because
    nothing downstream re-validates analyzer metadata. A hostile input only
    has to make the summary large enough to trip the per-artifact cap: an
    email with enough attachment filenames did it, and the resulting
    ``email_summary.json`` ended mid-string.

    Drop recorded entries instead, longest list first, and mark the record so
    a reader can tell it is partial. Returns ``None`` when not even a minimal
    record fits, so the caller omits the artifact rather than emitting broken
    JSON.
    """
    limit = max(1, int(limit))

    def encode(value: dict[str, Any]) -> bytes:
        return json.dumps(value, indent=2, sort_keys=True).encode("utf-8")

    encoded = encode(summary)
    if len(encoded) <= limit:
        return encoded

    trimmed = copy.deepcopy(summary)
    trimmed["truncated"] = True
    while len(encode(trimmed)) > limit:
        candidates = [
            (len(value), key)
            for key, value in trimmed.items()
            if isinstance(value, list) and value
        ]
        if not candidates:
            break
        _length, key = max(candidates)
        # Halve rather than pop: a summary with thousands of entries would
        # otherwise re-serialize thousands of times to converge.
        trimmed[key] = trimmed[key][: len(trimmed[key]) // 2]

    encoded = encode(trimmed)
    if len(encoded) <= limit:
        return encoded

    minimal = encode({"analyzer": summary.get("analyzer", ""), "truncated": True})
    return minimal if len(minimal) <= limit else None


class _Collector:
    def __init__(self, max_artifacts: int, max_total: int, max_item: int):
        self.max_artifacts = max(1, max_artifacts)
        self.max_total = max(1, max_total)
        self.max_item = max(1, max_item)
        self.total = 0
        self.items: list[tuple[str, bytes]] = []
        self.names: set[str] = set()

    def add(self, name: str, content: bytes) -> bool:
        if not content or len(self.items) >= self.max_artifacts:
            return False
        content = content[: self.max_item]
        if self.total + len(content) > self.max_total:
            return False
        candidate = _safe_name(name)
        stem, dot, suffix = candidate.partition(".")
        index = 2
        while candidate.lower() in self.names:
            candidate = f"{stem}_{index}{dot}{suffix}" if dot else f"{stem}_{index}"
            index += 1
        self.names.add(candidate.lower())
        self.items.append((candidate, content))
        self.total += len(content)
        return True


class EmailAnalyzer(Analyzer):
    """Parse RFC 5322/MIME mail and expose bodies and attachments."""

    _HEADER = re.compile(
        rb"(?im)^(?:from|to|subject|date|message-id|mime-version|content-type):"
    )

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = int(config.get("max_structured_artifacts", 32))
        self.max_total = int(config.get("max_structured_total_size", 16 << 20))
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))

    @property
    def name(self) -> str:
        return "Email"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"email_summary.json"})

    def can_analyze(self, data: bytes) -> bool:
        header = data[: 64 * 1024]
        return bool(
            b"\n\n" in header.replace(b"\r\n", b"\n") and self._HEADER.search(header)
        )

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if not self.can_analyze(data):
            return []
        try:
            message = BytesParser(policy=policy.default).parsebytes(data)
        except Exception:
            return []

        collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
        # Reserve the summary name so an attachment that sanitizes to the same
        # string is renamed by the collector instead of colliding with it.
        collector.names.add("email_summary.json")
        summary: dict[str, Any] = {
            "analyzer": "email",
            "subject": str(message.get("subject", ""))[:4096],
            "from": str(message.get("from", ""))[:4096],
            "to": str(message.get("to", ""))[:4096],
            "date": str(message.get("date", ""))[:256],
            "message_id": str(message.get("message-id", ""))[:512],
            "parts": [],
            "attachments": [],
        }
        parts: Iterable[Any] = message.walk() if message.is_multipart() else (message,)
        body_index = 0
        attachment_index = 0
        for part in parts:
            if part.is_multipart():
                continue
            content_type = str(part.get_content_type())
            filename = part.get_filename()
            disposition = str(part.get_content_disposition() or "")
            summary["parts"].append(
                {
                    "content_type": content_type,
                    "filename": str(filename or "")[:512],
                    "disposition": disposition,
                }
            )
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if not isinstance(payload, bytes) or not payload:
                continue
            if (
                filename
                or disposition == "attachment"
                or not content_type.startswith("text/")
            ):
                attachment_index += 1
                safe = _safe_name(str(filename or f"attachment_{attachment_index}.bin"))
                if collector.add(f"email_{safe}", payload):
                    summary["attachments"].append(safe)
                continue
            body_index += 1
            charset = part.get_content_charset() or "utf-8"
            try:
                normalized = payload.decode(charset, errors="replace").encode("utf-8")
            except LookupError:
                normalized = payload.decode("utf-8", errors="replace").encode("utf-8")
            collector.add(f"email_body_{body_index}.txt", normalized)

        encoded_summary = _bounded_summary(summary, self.max_item)
        if encoded_summary is not None:
            collector.items.insert(0, ("email_summary.json", encoded_summary))
        return collector.items[: self.max_artifacts]


class OfficeAnalyzer(Analyzer):
    """Inspect OOXML packages, relationships, macros, and embedded objects."""

    _OFFICE_PREFIXES = ("word/", "xl/", "ppt/")
    _REL_TARGET = re.compile(
        rb"(?is)<Relationship\b[^>]*\bTarget\s*=\s*['\"]([^'\"]+)['\"][^>]*>"
    )
    _TAG = re.compile(rb"<[^>]{1,8192}>")
    _FORMULA = re.compile(
        rb"(?is)<(?:[A-Za-z0-9_]+:)?f(?:\s[^>]*)?>(.*?)"
        rb"</(?:[A-Za-z0-9_]+:)?f\s*>"
    )
    _XLM_HIGH_RISK_FUNCTIONS = frozenset(
        {
            "CALL",
            "EXEC",
            "FOPEN",
            "FORMULA",
            "FORMULA.FILL",
            "FWRITE",
            "REGISTER",
            "REGISTER.ID",
            "RUN",
            "SEND.KEYS",
        }
    )

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = int(config.get("max_structured_artifacts", 32))
        self.max_total = int(config.get("max_structured_total_size", 16 << 20))
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))
        self.max_ratio = int(config.get("max_compression_ratio", 100))

    @property
    def name(self) -> str:
        return "OfficeOOXML"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"office_summary.json"})

    def can_analyze(self, data: bytes) -> bool:
        if not data.startswith(b"PK\x03\x04"):
            return False
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()[:4096]
        except (OSError, zipfile.BadZipFile):
            return False
        return "[Content_Types].xml" in names and any(
            name.startswith(self._OFFICE_PREFIXES) for name in names
        )

    def _safe_infos(self, archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
        output: list[zipfile.ZipInfo] = []
        total = 0
        for info in archive.infolist()[:4096]:
            if info.is_dir() or info.flag_bits & 0x1:
                continue
            if info.file_size > self.max_item:
                continue
            if (
                info.compress_size
                and info.file_size / info.compress_size > self.max_ratio
            ):
                continue
            if total + info.file_size > self.max_total:
                break
            output.append(info)
            total += info.file_size
        return output

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if not self.can_analyze(data):
            return []
        collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
        # Reserve the summary name so an archive member that sanitizes to the
        # same string is renamed by the collector instead of colliding with it.
        collector.names.add("office_summary.json")
        summary: dict[str, Any] = {
            "analyzer": "office_ooxml",
            "package_type": "unknown",
            "macro_present": False,
            "embedded_objects": [],
            "external_relationships": [],
            "suspicious_members": [],
            "xlm_formula_count": 0,
            "xlm_high_risk_functions": [],
            "xlm_macro_present": False,
            "xlm_macro_sheets": [],
        }
        xlm_lines: list[str] = []
        xlm_functions: set[str] = set()
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = self._safe_infos(archive)
                names = {info.filename for info in infos}
                if any(name.startswith("word/") for name in names):
                    summary["package_type"] = "word"
                elif any(name.startswith("xl/") for name in names):
                    summary["package_type"] = "excel"
                elif any(name.startswith("ppt/") for name in names):
                    summary["package_type"] = "powerpoint"

                for info in infos:
                    lowered = info.filename.lower()
                    interesting = (
                        lowered.endswith("vbaproject.bin")
                        or "/embeddings/" in lowered
                        or (
                            lowered.startswith("xl/macrosheets/")
                            and lowered.endswith(".xml")
                        )
                        or lowered.endswith(".rels")
                        or lowered.endswith(
                            ("document.xml", "workbook.xml", "presentation.xml")
                        )
                    )
                    if not interesting:
                        continue
                    try:
                        content = archive.read(info)
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        continue
                    if lowered.endswith("vbaproject.bin"):
                        summary["macro_present"] = True
                        summary["suspicious_members"].append(info.filename)
                        collector.add("office_vbaProject.bin", content)
                    elif lowered.startswith("xl/macrosheets/") and lowered.endswith(
                        ".xml"
                    ):
                        summary["macro_present"] = True
                        summary["xlm_macro_present"] = True
                        summary["xlm_macro_sheets"].append(info.filename)
                        summary["suspicious_members"].append(info.filename)
                        for match in self._FORMULA.finditer(content[: self.max_item]):
                            if len(xlm_lines) >= 256:
                                break
                            formula = html.unescape(
                                self._TAG.sub(b"", match.group(1)).decode(
                                    "utf-8", errors="replace"
                                )
                            ).strip()
                            if not formula:
                                continue
                            formula = formula[:4096]
                            xlm_lines.append(f"[{info.filename}] {formula}")
                            for function in re.findall(
                                r"(?i)(?<![A-Z0-9_.])([A-Z][A-Z0-9_.]{1,63})\s*\(",
                                formula,
                            ):
                                upper = function.upper()
                                if upper in self._XLM_HIGH_RISK_FUNCTIONS:
                                    xlm_functions.add(upper)
                    elif "/embeddings/" in lowered:
                        summary["embedded_objects"].append(info.filename)
                        collector.add(f"office_{_safe_name(info.filename)}", content)
                    elif lowered.endswith(".rels"):
                        for match in self._REL_TARGET.finditer(
                            content[: self.max_item]
                        ):
                            target = html.unescape(
                                match.group(1).decode("utf-8", errors="replace")
                            )
                            if "://" in target or target.lower().startswith(
                                ("file:", "\\\\")
                            ):
                                summary["external_relationships"].append(target[:4096])
                        collector.add(f"office_{_safe_name(info.filename)}", content)
                    else:
                        text = html.unescape(
                            self._TAG.sub(b" ", content).decode(
                                "utf-8", errors="replace"
                            )
                        )
                        text = re.sub(r"\s+", " ", text).strip()
                        if text:
                            collector.add(
                                "office_document_text.txt", text.encode("utf-8")
                            )
        except (OSError, zipfile.BadZipFile):
            return []

        summary["external_relationships"] = sorted(
            set(summary["external_relationships"])
        )[:256]
        summary["embedded_objects"] = sorted(set(summary["embedded_objects"]))[:256]
        summary["suspicious_members"] = sorted(set(summary["suspicious_members"]))[:256]
        summary["xlm_macro_sheets"] = sorted(set(summary["xlm_macro_sheets"]))[:256]
        summary["xlm_formula_count"] = len(xlm_lines)
        summary["xlm_high_risk_functions"] = sorted(xlm_functions)
        if xlm_lines:
            collector.add("office_xlm_macros.txt", "\n".join(xlm_lines).encode("utf-8"))
        encoded = _bounded_summary(summary, self.max_item)
        if encoded is not None:
            collector.items.insert(0, ("office_summary.json", encoded))
        return collector.items[: self.max_artifacts]


class RtfAnalyzer(Analyzer):
    """Extract text and embedded object data from Rich Text Format documents.

    The parser deliberately implements only the structural subset needed for
    static extraction. It never invokes an OLE server or renders the document,
    and every scan, group, artifact, and output is bounded.
    """

    _HEADER = re.compile(rb"^\s*\{\\rtf(?:1\b|\b)", re.IGNORECASE)
    _CONTROL = re.compile(rb"[a-zA-Z]+")
    _HEX = frozenset(b"0123456789abcdefABCDEF")
    _SKIP_TEXT_DESTINATIONS = frozenset(
        {
            "colortbl",
            "datastore",
            "filetbl",
            "fonttbl",
            "info",
            "listtable",
            "listoverridetable",
            "object",
            "objdata",
            "pict",
            "stylesheet",
            "themedata",
        }
    )
    _INTERESTING_DESTINATIONS = _SKIP_TEXT_DESTINATIONS | frozenset({"objclass"})
    _SUSPICIOUS_CONTROLS = (
        "datastore",
        "field",
        "filetbl",
        "fldinst",
        "objautlink",
        "objdata",
        "objemb",
        "object",
        "objupdate",
    )
    _MAGICS = (
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".ole"),
        (b"MZ", ".exe"),
        (b"PK\x03\x04", ".zip"),
        (b"%PDF-", ".pdf"),
    )
    _EXTERNAL_TARGET = re.compile(r"(?i)(?:https?://|file:/{0,2}|\\\\)[^\s<>\"{}]+")

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = int(config.get("max_structured_artifacts", 32))
        self.max_total = int(config.get("max_structured_total_size", 16 << 20))
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))
        self.max_group_depth = 256

    @property
    def name(self) -> str:
        return "RTF"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"rtf_summary.json"})

    def can_analyze(self, data: bytes) -> bool:
        return bool(self._HEADER.match(data[:64]))

    @classmethod
    def _destination(cls, data: bytes, position: int) -> tuple[str, int]:
        size = len(data)
        while position < size and data[position] in b" \t\r\n":
            position += 1
        if data[position : position + 2] == b"\\*":
            position += 2
            while position < size and data[position] in b" \t\r\n":
                position += 1
        if position >= size or data[position] != 0x5C:
            return "", position
        match = cls._CONTROL.match(data, position + 1)
        if not match:
            return "", position
        end = match.end()
        while end < size and data[end] in b"-0123456789":
            end += 1
        if end < size and data[end] == 0x20:
            end += 1
        return match.group().decode("ascii").lower(), end

    def _groups(
        self, data: bytes
    ) -> tuple[list[tuple[str, int, int]], int, bool, bool]:
        """Return interesting destination spans and structural observations."""
        groups: list[tuple[str, int, int]] = []
        stack: list[tuple[str, int]] = []
        overflow_depth = 0
        maximum_depth = 0
        depth_limited = False
        position = 0
        size = len(data)
        while position < size:
            value = data[position]
            if value == 0x7B:  # {
                if overflow_depth or len(stack) >= self.max_group_depth:
                    overflow_depth += 1
                    depth_limited = True
                else:
                    destination, content_start = self._destination(data, position + 1)
                    stack.append((destination, content_start))
                    maximum_depth = max(maximum_depth, len(stack))
                position += 1
                continue
            if value == 0x7D:  # }
                if overflow_depth:
                    overflow_depth -= 1
                elif stack:
                    destination, content_start = stack.pop()
                    if destination in self._INTERESTING_DESTINATIONS:
                        groups.append((destination, content_start, position))
                position += 1
                continue
            if value != 0x5C:  # backslash
                position += 1
                continue
            match = self._CONTROL.match(data, position + 1)
            if not match:
                position += 2
                continue
            word = match.group().lower()
            end = match.end()
            sign = 1
            if end < size and data[end] == 0x2D:
                sign = -1
                end += 1
            number_start = end
            while end < size and 0x30 <= data[end] <= 0x39:
                end += 1
            number = None
            if end > number_start:
                number = sign * int(data[number_start:end])
            if end < size and data[end] == 0x20:
                end += 1
            if word == b"bin" and number is not None and number > 0:
                position = min(size, end + number)
            else:
                position = end
        balanced = not stack and overflow_depth == 0
        return groups, maximum_depth, balanced, depth_limited

    @classmethod
    def _decode_objdata(cls, content: bytes, limit: int) -> bytes:
        output = bytearray()
        nibbles = bytearray()
        position = 0
        size = len(content)
        while position < size and len(output) < limit:
            value = content[position]
            if value in cls._HEX:
                nibbles.append(value)
                if len(nibbles) == 2:
                    output.append(int(nibbles.decode("ascii"), 16))
                    nibbles.clear()
                position += 1
                continue
            if value != 0x5C:
                position += 1
                continue
            nibbles.clear()
            if content[position + 1 : position + 2] == b"'" and position + 3 < size:
                pair = content[position + 2 : position + 4]
                if all(item in cls._HEX for item in pair):
                    output.append(int(pair.decode("ascii"), 16))
                    position += 4
                    continue
            match = cls._CONTROL.match(content, position + 1)
            if not match:
                position += 2
                continue
            word = match.group().lower()
            end = match.end()
            number_start = end
            while end < size and 0x30 <= content[end] <= 0x39:
                end += 1
            number = int(content[number_start:end] or b"0")
            if end < size and content[end] == 0x20:
                end += 1
            if word == b"bin" and number > 0:
                chunk = content[end : min(size, end + number)]
                output.extend(chunk[: max(0, limit - len(output))])
                position = end + len(chunk)
            else:
                position = end
        return bytes(output[:limit])

    @classmethod
    def _carve_payload(cls, content: bytes) -> tuple[bytes, str]:
        candidates = [
            (offset, suffix)
            for magic, suffix in cls._MAGICS
            if (offset := content.find(magic)) >= 0
        ]
        if not candidates:
            return content, ".bin"
        offset, suffix = min(candidates, key=lambda item: item[0])
        return content[offset:], suffix

    @classmethod
    def _plain_text(
        cls, data: bytes, excluded: list[tuple[int, int]], limit: int
    ) -> bytes:
        output: list[str] = []
        position = 0
        excluded_index = 0
        size = len(data)
        while position < size and len(output) < limit:
            while (
                excluded_index < len(excluded)
                and excluded[excluded_index][1] <= position
            ):
                excluded_index += 1
            if excluded_index < len(excluded):
                start, end = excluded[excluded_index]
                if start <= position < end:
                    position = end
                    continue
            value = data[position]
            if value in (0x7B, 0x7D):
                position += 1
                continue
            if value != 0x5C:
                if value in (0x0A, 0x0D):
                    output.append("\n")
                elif value >= 0x20:
                    output.append(bytes((value,)).decode("cp1252", errors="replace"))
                position += 1
                continue
            if position + 1 >= size:
                break
            symbol = data[position + 1]
            if symbol in b"{}\\":
                output.append(chr(symbol))
                position += 2
                continue
            if symbol == 0x27 and position + 3 < size:
                pair = data[position + 2 : position + 4]
                if all(item in cls._HEX for item in pair):
                    output.append(
                        bytes((int(pair.decode("ascii"), 16),)).decode("cp1252")
                    )
                    position += 4
                    continue
            match = cls._CONTROL.match(data, position + 1)
            if not match:
                if symbol == 0x7E:
                    output.append(" ")
                elif symbol == 0x5F:
                    output.append("-")
                position += 2
                continue
            word = match.group().decode("ascii").lower()
            end = match.end()
            sign = 1
            if end < size and data[end] == 0x2D:
                sign = -1
                end += 1
            number_start = end
            while end < size and 0x30 <= data[end] <= 0x39:
                end += 1
            number = None
            if end > number_start:
                number = sign * int(data[number_start:end])
            if end < size and data[end] == 0x20:
                end += 1
            if word in {"line", "par", "row"}:
                output.append("\n")
            elif word in {"cell", "tab"}:
                output.append("\t")
            elif word == "u" and number is not None:
                codepoint = number if number >= 0 else number + 65536
                if 0 <= codepoint <= 0x10FFFF:
                    output.append(chr(codepoint))
                # RTF's default \uc1 fallback is one source character.
                if end < size and data[end] not in b"{}\\\r\n":
                    end += 1
            elif word == "bin" and number is not None and number > 0:
                end = min(size, end + number)
            position = end
        text = "".join(output)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text).strip()
        return text.encode("utf-8")[:limit]

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if not self.can_analyze(data):
            return []
        scanned = data[: self.max_total]
        groups, maximum_depth, balanced, depth_limited = self._groups(scanned)
        collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
        collector.names.add("rtf_summary.json")

        excluded = sorted(
            (start, end + 1)
            for destination, start, end in groups
            if destination in self._SKIP_TEXT_DESTINATIONS
        )
        text = self._plain_text(scanned, excluded, self.max_item)
        if text:
            collector.add("rtf_text.txt", text)

        object_records: list[dict[str, Any]] = []
        seen_hashes: set[str] = set()
        object_groups = [item for item in groups if item[0] == "objdata"]
        for _, start, end in object_groups:
            decoded = self._decode_objdata(scanned[start:end], self.max_item)
            if not decoded:
                continue
            payload, suffix = self._carve_payload(decoded)
            digest = sha256(payload).hexdigest()
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            name = f"rtf_object_{len(object_records) + 1:03d}{suffix}"
            stored = collector.add(name, payload)
            object_records.append(
                {
                    "artifact": name if stored else None,
                    "decoded_size": len(decoded),
                    "payload_offset": len(decoded) - len(payload),
                    "sha256": digest,
                    "stored": stored,
                    "type": suffix.removeprefix("."),
                }
            )

        classes = sorted(
            {
                self._plain_text(scanned[start:end], [], 512)
                .decode("utf-8", errors="replace")
                .strip()
                for destination, start, end in groups
                if destination == "objclass"
            }
            - {""}
        )[:64]
        lowered = scanned.lower()
        control_counts = {
            name: len(re.findall(rb"\\" + name.encode() + rb"\b", lowered))
            for name in self._SUSPICIOUS_CONTROLS
        }
        decoded_text = text.decode("utf-8", errors="replace")
        external_targets = sorted(set(self._EXTERNAL_TARGET.findall(decoded_text)))[
            :256
        ]
        object_types = sorted({str(item["type"]) for item in object_records})
        active_content = {
            "auto_linked_object": bool(control_counts.get("objautlink")),
            "embedded_executable": "exe" in object_types,
            "embedded_object": bool(object_records),
            "external_target": bool(external_targets),
            "legacy_equation_object": any(
                value.lower().startswith("equation.") for value in classes
            ),
            "object_update_requested": bool(control_counts.get("objupdate")),
        }
        summary = {
            "analyzer": "rtf",
            "active_content": active_content,
            "balanced_groups": balanced,
            "depth_limited": depth_limited,
            "external_targets": external_targets,
            "input_truncated": len(data) > len(scanned),
            "maximum_group_depth": maximum_depth,
            "object_classes": classes,
            "object_group_count": len(object_groups),
            "object_types": object_types,
            "objects": object_records,
            "suspicious_controls": {
                name: count for name, count in control_counts.items() if count
            },
            "execution_performed": False,
        }
        encoded = _bounded_summary(summary, self.max_item)
        if encoded is not None:
            collector.items.insert(0, ("rtf_summary.json", encoded))
        return collector.items[: self.max_artifacts]


class MsiAnalyzer(Analyzer):
    """Inspect Windows Installer CFB databases without executing custom actions."""

    _PAYLOAD_MAGICS = (
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".ole"),
        (b"MZ", ".exe"),
        (b"PK\x03\x04", ".zip"),
        (b"MSCF", ".cab"),
        (b"%PDF-", ".pdf"),
    )
    _ASCII = re.compile(rb"[\x20-\x7e]{4,4096}")
    _UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,2048}")
    _NAME_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
    _COMMAND_MARKERS = (
        "cmd.exe",
        "cscript",
        "mshta",
        "msiexec",
        "powershell",
        "pwsh",
        "regsvr32",
        "rundll32",
        "wscript",
    )

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = int(config.get("max_structured_artifacts", 32))
        self.max_total = int(config.get("max_structured_total_size", 16 << 20))
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))

    @property
    def name(self) -> str:
        return "MSI"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"msi_summary.json"})

    @classmethod
    def _decode_stream_name(cls, value: str) -> tuple[str, bool]:
        """Decode MSI's packed CFB stream-name representation."""

        table_stream = value.startswith("\u4840")
        position = 1 if table_stream else 0
        decoded: list[str] = []
        for character in value[position:]:
            codepoint = ord(character)
            if 0x3800 <= codepoint < 0x4800:
                packed = codepoint - 0x3800
                decoded.append(cls._NAME_ALPHABET[packed & 0x3F])
                decoded.append(cls._NAME_ALPHABET[(packed >> 6) & 0x3F])
            elif 0x4800 <= codepoint < 0x4840:
                decoded.append(cls._NAME_ALPHABET[codepoint - 0x4800])
            else:
                decoded.append(character)
        return "".join(decoded), table_stream

    @classmethod
    def _decoded_path(cls, path: str) -> tuple[str, bool]:
        parts = path.replace("\\", "/").split("/")
        decoded_parts: list[str] = []
        table_stream = False
        for part in parts:
            decoded, is_table = cls._decode_stream_name(part)
            decoded_parts.append(decoded)
            table_stream = table_stream or is_table
        return "/".join(decoded_parts), table_stream

    @classmethod
    def _leaf(cls, path: str) -> str:
        decoded, _ = cls._decoded_path(path)
        return decoded.rsplit("/", 1)[-1].lower()

    def _reader(self, data: bytes) -> CFBReader | None:
        if len(data) < 512 or not data.startswith(CFB_SIGNATURE):
            return None
        try:
            return CFBReader(data, max_total_bytes=self.max_total)
        except (CFBError, IndexError, OSError, OverflowError, ValueError, struct.error):
            return None

    def can_analyze(self, data: bytes) -> bool:
        reader = self._reader(data)
        if reader is None:
            return False
        try:
            leaves = {self._leaf(path) for path, _ in reader.streams()[:2048]}
        except (CFBError, IndexError, OSError, OverflowError, ValueError, struct.error):
            return False
        return {"_stringpool", "_stringdata"}.issubset(leaves)

    @staticmethod
    def _encoding(code_page: int) -> tuple[str, int]:
        if code_page == 0:
            return "utf-16-le", 2
        if code_page in {65001, 1200}:
            return ("utf-8", 1) if code_page == 65001 else ("utf-16-le", 2)
        try:
            "".encode(f"cp{code_page}")
            return f"cp{code_page}", 1
        except LookupError:
            return "cp1252", 1

    def _strings(self, pool: bytes, string_data: bytes) -> tuple[int, list[str]]:
        if len(pool) < 4:
            return 0, []
        code_page = struct.unpack_from("<H", pool, 0)[0]
        encoding, width = self._encoding(code_page)
        values: list[str] = []
        data_position = 0
        # MSI pool entries are (character length, reference count) uint16
        # pairs after a four-byte header. Long-string extensions are skipped
        # rather than guessed; fallback carving below still exposes text.
        for position in range(4, min(len(pool), 4 + 4096 * 4), 4):
            if position + 4 > len(pool):
                break
            length, references = struct.unpack_from("<HH", pool, position)
            byte_length = length * width
            if byte_length > self.max_item or data_position + byte_length > len(
                string_data
            ):
                break
            chunk = string_data[data_position : data_position + byte_length]
            data_position += byte_length
            if not length or not references:
                continue
            value = chunk.decode(encoding, errors="replace").strip("\x00\r\n ")
            if value:
                values.append(value[:4096])

        if not values:
            for pattern, encoding_name in (
                (self._ASCII, "ascii"),
                (self._UTF16, "utf-16-le"),
            ):
                for match in pattern.finditer(string_data[: self.max_item]):
                    values.append(match.group().decode(encoding_name, errors="replace"))
                    if len(values) >= 4096:
                        break
                if len(values) >= 4096:
                    break
        return code_page, sorted(set(values))[:4096]

    @classmethod
    def _payload(cls, content: bytes) -> tuple[bytes, str] | None:
        candidates = [
            (offset, suffix)
            for magic, suffix in cls._PAYLOAD_MAGICS
            if (offset := content[:4096].find(magic)) >= 0
        ]
        if not candidates:
            return None
        offset, suffix = min(candidates, key=lambda item: item[0])
        return content[offset:], suffix

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        reader = self._reader(data)
        if reader is None:
            return []
        try:
            streams = reader.streams()[:2048]
        except (CFBError, IndexError, OSError, OverflowError, ValueError, struct.error):
            return []
        stream_records = [
            (path, *self._decoded_path(path), entry) for path, entry in streams
        ]
        leaves = {
            decoded.rsplit("/", 1)[-1].lower(): (path, decoded, entry)
            for path, decoded, _is_table, entry in stream_records
        }
        if not {"_stringpool", "_stringdata"}.issubset(leaves):
            return []

        collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
        collector.names.add("msi_summary.json")
        try:
            pool = reader.read_stream(leaves["_stringpool"][2])[: self.max_item]
            string_data = reader.read_stream(leaves["_stringdata"][2])[: self.max_item]
        except (CFBError, IndexError, OSError, OverflowError, ValueError, struct.error):
            pool, string_data = b"", b""
        code_page, strings = self._strings(pool, string_data)
        if strings:
            collector.add("msi_strings.txt", "\n".join(strings).encode("utf-8"))

        payloads: list[dict[str, Any]] = []
        payload_hashes: set[str] = set()
        for path, decoded_path, _is_table, entry in stream_records:
            if decoded_path.rsplit("/", 1)[-1].lower() in {
                "_stringpool",
                "_stringdata",
            }:
                continue
            if entry.size <= 0 or entry.size > self.max_total:
                continue
            try:
                content = reader.read_stream(entry)[: self.max_item]
            except (
                CFBError,
                IndexError,
                OSError,
                OverflowError,
                ValueError,
                struct.error,
            ):
                continue
            carved = self._payload(content)
            if carved is None:
                continue
            payload, suffix = carved
            digest = sha256(payload).hexdigest()
            if digest in payload_hashes:
                continue
            payload_hashes.add(digest)
            name = f"msi_payload_{len(payloads) + 1:03d}{suffix}"
            stored = collector.add(name, payload)
            payloads.append(
                {
                    "artifact": name if stored else None,
                    "sha256": digest,
                    "source_stream": decoded_path[:512],
                    "source_stream_raw": (path[:512] if path != decoded_path else None),
                    "stored": stored,
                    "type": suffix.removeprefix("."),
                }
            )

        stream_names = sorted(path[:512] for path, _ in streams)[:512]
        decoded_stream_names = sorted(
            {decoded_path[:512] for _, decoded_path, _, _ in stream_records}
        )[:512]
        table_names = sorted(
            {
                decoded_path.rsplit("/", 1)[-1][:128]
                for _, decoded_path, is_table, _ in stream_records
                if is_table
            }
        )[:256]
        sequence_tables = sorted(
            name for name in table_names if name.lower().endswith("sequence")
        )[:32]
        binary_streams = sorted(
            name[:256]
            for name in decoded_stream_names
            if name.lower().startswith("binary.")
        )[:128]
        command_strings = sorted(
            {
                value[:512]
                for value in strings
                if any(marker in value.lower() for marker in self._COMMAND_MARKERS)
            }
        )[:32]
        custom_action_table_present = any(
            name.lower() == "customaction" for name in table_names
        )
        summary = {
            "analyzer": "msi",
            "code_page": code_page,
            "custom_action_evidence": {
                "binary_streams": binary_streams,
                "command_strings": command_strings,
                "custom_action_table_present": custom_action_table_present,
                "execution_surface_present": bool(
                    custom_action_table_present or command_strings
                ),
                "sequence_tables": sequence_tables,
            },
            "decoded_stream_names": decoded_stream_names,
            "execution_performed": False,
            "payloads": payloads,
            "stream_count": len(streams),
            "stream_names": stream_names,
            "string_count": len(strings),
            "table_names": table_names,
        }
        encoded = _bounded_summary(summary, self.max_item)
        if encoded is not None:
            collector.items.insert(0, ("msi_summary.json", encoded))
        return collector.items[: self.max_artifacts]


class OneNoteAnalyzer(Analyzer):
    """Recover bounded embedded file objects from OneNote section files."""

    # GUIDs use the mixed-endian byte representation required by MS-ONESTORE.
    _FILE_TYPE = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
    _REVISION_FORMAT = bytes.fromhex("3fdd9a101b91f549a5d01791edc8aed8")
    _PACKAGE_FORMAT = bytes.fromhex("2fe98d63d4a6c14b9a36b3fc2511a5b7")
    _OBJECT_HEADER = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")
    _OBJECT_FOOTER = bytes.fromhex("22a7fb71790f0b4abb13899256426b24")
    _PAYLOAD_MAGICS = (
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", ".ole"),
        (b"MZ", ".exe"),
        (b"PK\x03\x04", ".zip"),
        (b"MSCF", ".cab"),
        (b"%PDF-", ".pdf"),
        (b"{\\rtf", ".rtf"),
    )
    _ASCII = re.compile(rb"[\x20-\x7e]{6,4096}")
    _UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,2048}")

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = int(config.get("max_structured_artifacts", 32))
        self.max_total = int(config.get("max_structured_total_size", 16 << 20))
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))

    @property
    def name(self) -> str:
        return "OneNote"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"onenote_summary.json"})

    def can_analyze(self, data: bytes) -> bool:
        if len(data) < 1024 or not data.startswith(self._FILE_TYPE):
            return False
        return data[48:64] in {self._REVISION_FORMAT, self._PACKAGE_FORMAT}

    @classmethod
    def _suffix(cls, payload: bytes) -> str:
        for magic, suffix in cls._PAYLOAD_MAGICS:
            if payload.startswith(magic):
                return suffix
        return ".bin"

    def _objects(self, scanned: bytes) -> list[tuple[int, bytes]]:
        objects: list[tuple[int, bytes]] = []
        position = 0
        while len(objects) < min(self.max_artifacts, 128):
            start = scanned.find(self._OBJECT_HEADER, position)
            if start < 0:
                break
            position = start + len(self._OBJECT_HEADER)
            if start + 36 > len(scanned):
                break
            length = struct.unpack_from("<Q", scanned, start + 16)[0]
            if length > self.max_item:
                continue
            data_start = start + 36
            data_end = data_start + length
            if data_end > len(scanned):
                continue
            footer = scanned.find(
                self._OBJECT_FOOTER,
                data_end,
                min(len(scanned), data_end + 7 + len(self._OBJECT_FOOTER)),
            )
            if footer < 0 or any(scanned[start + 24 : start + 36]):
                continue
            objects.append((start, scanned[data_start:data_end]))
            position = footer + len(self._OBJECT_FOOTER)
        return objects

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if not self.can_analyze(data):
            return []
        scanned = data[: self.max_total]
        collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
        collector.names.add("onenote_summary.json")

        object_records: list[dict[str, Any]] = []
        hashes: set[str] = set()
        for offset, payload in self._objects(scanned):
            digest = sha256(payload).hexdigest()
            if digest in hashes:
                continue
            hashes.add(digest)
            suffix = self._suffix(payload)
            name = f"onenote_file_{len(object_records) + 1:03d}{suffix}"
            stored = collector.add(name, payload)
            object_records.append(
                {
                    "artifact": name if stored else None,
                    "offset": offset,
                    "sha256": digest,
                    "size": len(payload),
                    "stored": stored,
                    "type": suffix.removeprefix("."),
                }
            )

        strings: set[str] = set()
        for pattern, encoding_name in (
            (self._ASCII, "ascii"),
            (self._UTF16, "utf-16-le"),
        ):
            for match in pattern.finditer(scanned):
                strings.add(match.group().decode(encoding_name, errors="replace"))
                if len(strings) >= 4096:
                    break
            if len(strings) >= 4096:
                break
        bounded_strings = sorted(strings)[:4096]
        if bounded_strings:
            collector.add(
                "onenote_strings.txt", "\n".join(bounded_strings).encode("utf-8")
            )

        summary = {
            "analyzer": "onenote",
            "embedded_file_count": len(object_records),
            "embedded_files": object_records,
            "execution_performed": False,
            "file_format": (
                "revision" if data[48:64] == self._REVISION_FORMAT else "package"
            ),
            "input_truncated": len(data) > len(scanned),
            "string_count": len(bounded_strings),
        }
        encoded = _bounded_summary(summary, self.max_item)
        if encoded is not None:
            collector.items.insert(0, ("onenote_summary.json", encoded))
        return collector.items[: self.max_artifacts]


class ScriptAnalyzer(Analyzer):
    """Recognize and statically normalize suspicious script content."""

    _LANGUAGE_PATTERNS: dict[str, tuple[bytes, ...]] = {
        "powershell": (
            b"powershell",
            b"invoke-",
            b"new-object",
            b"$env:",
            b"-encodedcommand",
        ),
        "javascript": (
            b"<script",
            b"function ",
            b"fromcharcode",
            b"activexobject",
            b"eval(",
        ),
        "vbscript": (b"createobject(", b"wscript.", b"cscript", b"dim "),
        "batch": (b"@echo off", b"%comspec%", b"cmd.exe /c", b"setlocal"),
        "shell": (b"#!/bin/", b"curl ", b"wget ", b"chmod +x", b"/bin/sh"),
        "python": (b"import subprocess", b"os.system(", b"exec(", b"base64.b64decode"),
    }
    _FEATURES: dict[str, bytes] = {
        "download": rb"(?i)https?://|downloadstring|\biwr\b|invoke-webrequest|\bcurl\b|\bwget\b",
        "execution": rb"(?i)invoke-expression|\biex\b|eval\s*\(|exec\s*\(|createprocess|shell\s*\(",
        "persistence": rb"(?i)currentversion\\run|schtasks|crontab|startup",
        "obfuscation": rb"(?i)fromcharcode|encodedcommand|base64|%u[0-9a-f]{4}|\\x[0-9a-f]{2}",
        "credential_access": rb"(?i)lsass|mimikatz|credential|sam\\|security\\policy",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))

    @property
    def name(self) -> str:
        return "Script"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"script_summary.json"})

    def _languages(self, data: bytes) -> list[str]:
        lowered = data[: self.max_item].lower()
        return sorted(
            language
            for language, markers in self._LANGUAGE_PATTERNS.items()
            if sum(marker in lowered for marker in markers) >= 2
            or (language == "shell" and lowered.startswith(b"#!"))
        )

    def can_analyze(self, data: bytes) -> bool:
        if not data or len(data) > self.max_item:
            return False
        if data.lstrip().startswith(b'{\n  "analyzer": "script"'):
            return False
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return bool(self._languages(data))

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        languages = self._languages(data)
        if not languages:
            return []
        features = sorted(
            name for name, pattern in self._FEATURES.items() if re.search(pattern, data)
        )
        artifacts: list[tuple[str, bytes]] = []
        for label, decoder in (
            ("powershell_decoded.txt", PowerShellEncodedCommandDecoder()),
            ("javascript_normalized.txt", JavaScriptEscapeDecoder()),
            ("javascript_emulated.txt", JavaScriptEmulationDecoder()),
            ("unicode_normalized.txt", UnicodeEscapeDecoder()),
        ):
            if decoder.can_decode(data):
                output, success = decoder.decode(data)
                if success and output != data:
                    artifacts.append((label, output[: self.max_item]))
        summary = {
            "analyzer": "script",
            "languages": languages,
            "features": features,
            "deobfuscated_artifacts": [name for name, _ in artifacts],
            "execution_performed": False,
        }
        return [
            (
                "script_summary.json",
                json.dumps(summary, indent=2, sort_keys=True).encode(),
            ),
            *artifacts,
        ]


class LnkAnalyzer(Analyzer):
    """Parse Windows Shell Link metadata and recover path-like strings."""

    _CLSID = bytes.fromhex("0114020000000000c000000000000046")
    _ASCII = re.compile(rb"[\x20-\x7e]{4,4096}")
    _UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,2048}")

    @property
    def name(self) -> str:
        return "WindowsLNK"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"lnk_metadata.json"})

    def can_analyze(self, data: bytes) -> bool:
        return (
            len(data) >= 76
            and data[:4] == b"L\x00\x00\x00"
            and data[4:20] == self._CLSID
        )

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if not self.can_analyze(data):
            return []
        flags, attributes = struct.unpack_from("<II", data, 20)
        file_size, icon_index, show_command = struct.unpack_from("<III", data, 52)
        strings = {
            match.group().decode("ascii", errors="replace")
            for match in self._ASCII.finditer(data[: 4 << 20])
        }
        strings.update(
            match.group().decode("utf-16-le", errors="replace")
            for match in self._UTF16.finditer(data[: 4 << 20])
        )
        interesting = sorted(
            value[:4096]
            for value in strings
            if "\\" in value
            or "://" in value
            or value.lower().endswith(
                (".exe", ".dll", ".ps1", ".js", ".vbs", ".bat", ".cmd")
            )
        )[:256]
        summary = {
            "analyzer": "windows_lnk",
            "link_flags": f"0x{flags:08x}",
            "file_attributes": f"0x{attributes:08x}",
            "target_file_size": file_size,
            "icon_index": icon_index,
            "show_command": show_command,
            "strings": interesting,
            "execution_performed": False,
        }
        return [
            (
                "lnk_metadata.json",
                json.dumps(summary, indent=2, sort_keys=True).encode(),
            )
        ]


class OptionalArchiveAnalyzer(Analyzer):
    """Extract 7z, RAR, ISO, and CAB members with optional libraries."""

    _SEVEN_ZIP = b"7z\xbc\xaf'\x1c"
    _RAR = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")
    _CAB = b"MSCF"

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = int(config.get("max_structured_artifacts", 32))
        self.max_total = int(config.get("max_structured_total_size", 16 << 20))
        self.max_item = int(config.get("max_structured_artifact_size", 4 << 20))
        self.max_ratio = int(config.get("max_compression_ratio", 100))

    @property
    def name(self) -> str:
        return "OptionalArchive"

    def can_analyze(self, data: bytes) -> bool:
        return bool(
            data.startswith((self._SEVEN_ZIP, *self._RAR, self._CAB))
            or (len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001")
        )

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if data.startswith(self._SEVEN_ZIP):
            return self._seven_zip(data)
        if data.startswith(self._RAR):
            return self._rar(data)
        if data.startswith(self._CAB):
            return self._cab(data)
        if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
            return self._iso(data)
        return []

    def _cab(self, data: bytes) -> list[tuple[str, bytes]]:
        try:
            from cabarchive import CabArchive  # type: ignore[import-not-found]

            archive = CabArchive(data)
            collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
            for name in sorted(archive):
                item = archive[name]
                content = bytes(item.buf)
                if len(content) <= self.max_item:
                    collector.add(_safe_name(str(name)), content)
            return collector.items
        except Exception:
            return []

    def _seven_zip(self, data: bytes) -> list[tuple[str, bytes]]:
        try:
            import py7zr  # type: ignore[import-not-found]

            with py7zr.SevenZipFile(io.BytesIO(data), mode="r") as archive:
                selected: list[tuple[str, PurePosixPath]] = []
                selected_total = 0
                for info in sorted(archive.list(), key=lambda item: item.filename):
                    relative = _safe_archive_path(str(info.filename))
                    declared_size = int(info.uncompressed or 0)
                    compressed_size = int(info.compressed or 0)
                    if (
                        relative is None
                        or info.is_directory
                        or info.is_symlink
                        or declared_size <= 0
                        or declared_size > self.max_item
                        or selected_total + declared_size > self.max_total
                        or (
                            compressed_size
                            and declared_size / compressed_size > self.max_ratio
                        )
                    ):
                        continue
                    selected.append((str(info.filename), relative))
                    selected_total += declared_size
                    if len(selected) >= self.max_artifacts:
                        break

                if not selected:
                    return []

                collector = _Collector(
                    self.max_artifacts, self.max_total, self.max_item
                )
                with tempfile.TemporaryDirectory(prefix="titan-7z-") as directory:
                    archive.extract(
                        path=directory,
                        targets=[name for name, _ in selected],
                    )
                    root = Path(directory).resolve()
                    for name, relative in selected:
                        target = root.joinpath(*relative.parts)
                        if target.is_symlink():
                            continue
                        resolved = target.resolve()
                        if root not in resolved.parents or not resolved.is_file():
                            continue
                        with resolved.open("rb") as stream:
                            content = stream.read(self.max_item + 1)
                        if len(content) <= self.max_item:
                            collector.add(_safe_name(name), content)
                return collector.items
        except Exception:
            return []

    def _rar(self, data: bytes) -> list[tuple[str, bytes]]:
        try:
            import rarfile  # type: ignore[import-not-found]

            collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
            with rarfile.RarFile(io.BytesIO(data)) as archive:
                for info in archive.infolist()[: self.max_artifacts * 4]:
                    if info.isdir() or info.file_size > self.max_item:
                        continue
                    if (
                        info.compress_size
                        and info.file_size / info.compress_size > self.max_ratio
                    ):
                        continue
                    collector.add(_safe_name(info.filename), archive.read(info))
            return collector.items
        except Exception:
            return []

    def _iso(self, data: bytes) -> list[tuple[str, bytes]]:
        try:
            import pycdlib  # type: ignore[import-not-found]

            image = pycdlib.PyCdlib()
            image.open_fp(io.BytesIO(data))
            collector = _Collector(self.max_artifacts, self.max_total, self.max_item)
            try:
                for directory, _, files in image.walk(iso_path="/"):
                    for entry in files:
                        parent = str(directory).rstrip("/")
                        path = f"{parent}/{entry}"
                        record: Any = image.get_record(iso_path=path)
                        declared_size = int(record.data_length)
                        if (
                            declared_size <= 0
                            or declared_size > self.max_item
                            or collector.total + declared_size > self.max_total
                        ):
                            continue
                        output = io.BytesIO()
                        image.get_file_from_iso_fp(output, iso_path=path)
                        content = output.getvalue()
                        if len(content) <= self.max_item:
                            collector.add(_safe_name(path), content)
                        if len(collector.items) >= self.max_artifacts:
                            return collector.items
            finally:
                image.close()
            return collector.items
        except Exception:
            return []
