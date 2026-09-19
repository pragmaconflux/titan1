from abc import ABC, abstractmethod
from typing import Dict, Any, List, Protocol, Sequence, Tuple
import json
import copy
from hashlib import sha256
import zipfile
import tarfile
import io
import re
import struct

from ...utils.helpers import entropy, looks_like_zip


def bounded_summary(summary: dict[str, Any], limit: int) -> bytes | None:
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


class CarvedArtifact(Protocol):
    """A region a composing analyzer recovered from inside a host buffer.

    Declared structurally so the engine can consume carved artifacts without
    importing the carving module, which imports this one.
    """

    @property
    def name(self) -> str: ...

    @property
    def data(self) -> bytes: ...

    @property
    def offset(self) -> int: ...

    @property
    def encoding(self) -> str: ...


class Analyzer(ABC):
    """Base class for all analyzers."""

    @abstractmethod
    def can_analyze(self, data: bytes) -> bool:
        """Check if this analyzer can handle the data."""
        pass

    @abstractmethod
    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Analyze the data and return list of (name, content) tuples."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer."""
        pass

    @property
    def composes(self) -> bool:
        """Whether this analyzer runs *in addition to* the analyzer that claims
        the node, rather than competing for the single analyzer slot.

        The main loop stops at the first analyzer that claims a node, which is
        right for format analyzers (a ZIP is not also an RTF) but wrong for
        orthogonal passes like embedded-payload carving: a script is still a
        script when it also carries a base64 blob. Composing analyzers are run
        by their own pass and skipped by the main loop."""
        return False

    def carve(self, data: bytes) -> Sequence[CarvedArtifact]:
        """Return regions recovered from inside ``data``.

        Only called on analyzers that report ``composes``; the default keeps
        the contract on the interface rather than leaving the engine to reach
        for an attribute the base class never declares.
        """
        return []

    @property
    def metadata_artifact_names(self) -> frozenset:
        """Artifact names this analyzer generates itself (summaries, parsed
        metadata) rather than extracts from the input. The engine records
        these nodes for IOC extraction and reporting but never feeds them
        back through decoders, where analyzer-authored JSON can only ever
        produce false-positive decode nodes."""
        return frozenset()


class ZipAnalyzer(Analyzer):
    """ZIP file analyzer with comprehensive safety checks.

    Extraction is sequential and in archive order: the source is an in-memory
    BytesIO, so threads add no I/O parallelism (only GIL contention) while
    making result order — and therefore node ordering in reports —
    nondeterministic.
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.max_files = self.config.get("max_zip_files", 25)
        self.max_total_size = self.config.get(
            "max_zip_total_size", 10 * 1024 * 1024
        )  # 10MB
        self.max_file_size = self.config.get(
            "max_zip_file_size", 50 * 1024 * 1024
        )  # 50MB per file
        self.max_compression_ratio = self.config.get(
            "max_compression_ratio", 100
        )  # 100:1 max
        configured_passwords = self.config.get("zip_passwords", ["infected"])
        if isinstance(configured_passwords, str):
            configured_passwords = [configured_passwords]
        if not isinstance(configured_passwords, (list, tuple)):
            configured_passwords = []
        # Password attempts are an explicit, tightly bounded allowlist. Titan
        # does not brute-force archives, and oversized/non-text values are
        # ignored before any extraction work begins.
        self.passwords = tuple(
            password.encode("utf-8")
            for password in configured_passwords[:8]
            if isinstance(password, str) and 0 < len(password.encode("utf-8")) <= 128
        )

    def can_analyze(self, data: bytes) -> bool:
        return looks_like_zip(data)

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Analyze ZIP file with safety checks."""
        final_extracted: List[Tuple[str, bytes]] = []
        total_size = 0

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                # Pre-scan for safety issues
                safe_files = self._pre_scan_zip(z)
                if not safe_files:
                    return []  # No safe files found

                extracted = self._extract_sequential(z, safe_files)

                # Apply final size limits and path sanitization
                for filename, content in extracted:
                    if len(final_extracted) >= self.max_files:
                        break

                    content_size = len(content)
                    if content_size > self.max_file_size:
                        continue
                    if total_size + content_size > self.max_total_size:
                        break

                    # Path traversal protection
                    safe_filename = self._sanitize_filename(filename)
                    final_extracted.append((safe_filename, content))
                    total_size += content_size

        except Exception:
            # Invalid ZIP or other error
            pass

        return final_extracted

    def _extract_sequential(
        self, zip_file: zipfile.ZipFile, safe_files: List[zipfile.ZipInfo]
    ) -> List[Tuple[str, bytes]]:
        """Extract files sequentially."""
        extracted = []
        for info in safe_files:
            passwords = self.passwords if info.flag_bits & 0x1 else (None,)
            for password in passwords:
                try:
                    content = zip_file.read(info, pwd=password)
                    extracted.append((info.filename, content))
                    break
                except (RuntimeError, NotImplementedError, zipfile.BadZipFile):
                    # Wrong password, unsupported encryption, or corrupt entry.
                    continue
        return extracted

    def _pre_scan_zip(self, zip_file: zipfile.ZipFile) -> List[zipfile.ZipInfo]:
        """Pre-scan ZIP contents for safety issues. Returns safe entries."""
        safe_files = []
        # Track the running total incrementally. Recomputing
        # ``sum(getinfo(f).file_size ...)`` on every iteration made this O(n^2):
        # a small crafted archive with many tiny entries (which never trip the
        # total-size cap) turned pre-scan into a multi-minute CPU hang.
        current_safe_size = 0

        for info in zip_file.infolist():
            if len(safe_files) >= self.max_files:
                break

            # Skip directories
            if info.is_dir():
                continue

            # Check for path traversal attacks
            if ".." in info.filename or info.filename.startswith("/"):
                continue

            # Check compression ratio (zip bomb detection)
            if info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > self.max_compression_ratio:
                    # Suspicious compression ratio - likely zip bomb
                    continue

            # Check for unusually large uncompressed files
            if info.file_size > self.max_file_size:
                continue

            # Check for files that would make total size too large
            if current_safe_size + info.file_size > self.max_total_size:
                continue

            safe_files.append(info)
            current_safe_size += info.file_size

        return safe_files

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal and other issues."""
        import os

        # Remove path separators and normalize
        safe_name = os.path.basename(filename)

        # Remove any remaining dangerous characters
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._- ")

        # Ensure it's not empty
        if not safe_name:
            safe_name = "extracted_file"

        return safe_name

    @property
    def name(self) -> str:
        return "ZIP"


class TarAnalyzer(Analyzer):
    """TAR file analyzer with comprehensive safety checks.

    Extraction is sequential: tarfile.TarFile shares one seekable file object
    with no internal locking, so concurrent extractfile() reads can interleave
    seeks and silently corrupt extracted content (unlike zipfile, tarfile is
    not thread-safe for reads).
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.max_files = self.config.get("max_tar_files", 25)
        self.max_total_size = self.config.get(
            "max_tar_total_size", 10 * 1024 * 1024
        )  # 10MB
        self.max_file_size = self.config.get(
            "max_tar_file_size", 50 * 1024 * 1024
        )  # 50MB per file
        self.max_compression_ratio = self.config.get(
            "max_compression_ratio", 100
        )  # 100:1 max

    def can_analyze(self, data: bytes) -> bool:
        # The ustar magic lives at offset 257 of the 512-byte tar header. Both
        # the POSIX ("ustar\x00") and GNU ("ustar  ") variants begin with
        # b"ustar" there, so match that prefix to cover both.
        return len(data) >= 262 and data[257:262] == b"ustar"

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Analyze TAR file with safety checks."""
        final_extracted: List[Tuple[str, bytes]] = []
        total_size = 0

        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                # Pre-scan for safety issues
                safe_members = self._pre_scan_tar(t)
                if not safe_members:
                    return []  # No safe files found

                extracted = self._extract_sequential(t, safe_members)

                # Apply final size limits and path sanitization
                for member, content in extracted:
                    if len(final_extracted) >= self.max_files:
                        break

                    content_size = len(content)
                    if content_size > self.max_file_size:
                        continue
                    if total_size + content_size > self.max_total_size:
                        break

                    # Path traversal protection
                    safe_filename = self._sanitize_filename(member.name)
                    final_extracted.append((safe_filename, content))
                    total_size += content_size

        except Exception:
            # Invalid TAR or other error
            pass

        return final_extracted

    def _extract_sequential(
        self, tar_file: tarfile.TarFile, safe_members: List[tarfile.TarInfo]
    ) -> List[Tuple[tarfile.TarInfo, bytes]]:
        """Extract files sequentially."""
        extracted = []
        for member in safe_members:
            try:
                content = tar_file.extractfile(member).read()
                extracted.append((member, content))
            except Exception:
                # Skip files that can't be read
                continue
        return extracted

    def _pre_scan_tar(self, tar_file: tarfile.TarFile) -> List[tarfile.TarInfo]:
        """Pre-scan TAR contents for safety issues. Returns list of safe TarInfo objects."""
        safe_members = []
        # Incremental running total; recomputing ``sum(m.size ...)`` per member
        # was O(n^2) and let a many-entry archive hang pre-scan.
        current_safe_size = 0

        # Iterate lazily instead of getmembers(), which materializes every
        # header even though only max_files entries can ever be extracted.
        for member in tar_file:
            if len(safe_members) >= self.max_files:
                break

            # Skip non-files
            if not member.isfile():
                continue

            # Check for path traversal attacks
            if ".." in member.name or member.name.startswith("/"):
                continue

            # TAR itself doesn't compress, so there is no per-member
            # compression ratio to check — just cap the member size.
            if member.size > self.max_file_size:
                continue

            # Check for files that would make total size too large
            if current_safe_size + member.size > self.max_total_size:
                continue

            safe_members.append(member)
            current_safe_size += member.size

        return safe_members

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal and other issues."""
        import os

        # Remove path separators and normalize
        safe_name = os.path.basename(filename)

        # Remove any remaining dangerous characters
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._- ")

        # Ensure it's not empty
        if not safe_name:
            safe_name = "extracted_file"

        return safe_name

    @property
    def name(self) -> str:
        return "TAR"


class PEAnalyzer(Analyzer):
    """PE (Portable Executable) file metadata analyzer."""

    _DOTNET_TABLE_NAMES = (
        "Module",
        "TypeRef",
        "TypeDef",
        "FieldPtr",
        "Field",
        "MethodPtr",
        "MethodDef",
        "ParamPtr",
        "Param",
        "InterfaceImpl",
        "MemberRef",
        "Constant",
        "CustomAttribute",
        "FieldMarshal",
        "DeclSecurity",
        "ClassLayout",
        "FieldLayout",
        "StandAloneSig",
        "EventMap",
        "EventPtr",
        "Event",
        "PropertyMap",
        "PropertyPtr",
        "Property",
        "MethodSemantics",
        "MethodImpl",
        "ModuleRef",
        "TypeSpec",
        "ImplMap",
        "FieldRVA",
        "ENCLog",
        "ENCMap",
        "Assembly",
        "AssemblyProcessor",
        "AssemblyOS",
        "AssemblyRef",
        "AssemblyRefProcessor",
        "AssemblyRefOS",
        "File",
        "ExportedType",
        "ManifestResource",
        "NestedClass",
        "GenericParam",
        "MethodSpec",
        "GenericParamConstraint",
    )
    _MAX_DOTNET_METADATA_SIZE = 64 << 20
    _MAX_DOTNET_STREAMS = 64
    _MAX_DOTNET_STRINGS = 512
    _MAX_DOTNET_STRING_BYTES = 64 << 10
    _MAX_DOTNET_REFERENCES = 1024
    _MAX_DOTNET_RESOURCES = 1024
    _MAX_DOTNET_RESOURCE_ARTIFACTS = 32
    _MAX_DOTNET_RESOURCE_ITEM_SIZE = 4 << 20
    _MAX_DOTNET_RESOURCE_TOTAL_SIZE = 16 << 20
    _MAX_INSTALLER_SCAN = 16 << 20
    _NSIS_SIGNATURE = b"\xef\xbe\xad\xdeNullsoftInst"
    _INNO_SETUP_ID = re.compile(
        rb"Inno Setup Setup Data \(([0-9]+(?:\.[0-9]+){1,3}[a-z]?)\)( \(u\))?"
    )
    _DOTNET_CODED_INDEXES = {
        "TypeDefOrRef": (2, (2, 1, 27)),
        "HasConstant": (2, (4, 8, 23)),
        "HasCustomAttribute": (
            5,
            (
                6,
                4,
                1,
                2,
                8,
                9,
                10,
                0,
                14,
                23,
                20,
                17,
                26,
                27,
                32,
                35,
                38,
                39,
                40,
                42,
                44,
            ),
        ),
        "HasFieldMarshal": (1, (4, 8)),
        "HasDeclSecurity": (2, (2, 6, 32)),
        "MemberRefParent": (3, (2, 1, 26, 6, 27)),
        "HasSemantics": (1, (20, 23)),
        "MethodDefOrRef": (1, (6, 10)),
        "MemberForwarded": (1, (4, 6)),
        "Implementation": (2, (38, 35, 39)),
        "CustomAttributeType": (3, (6, 10)),
        "ResolutionScope": (2, (0, 26, 35, 1)),
        "TypeOrMethodDef": (1, (2, 6)),
    }
    _DOTNET_TABLE_SCHEMAS = {
        0: ("u2", "str", "guid", "guid", "guid"),
        1: ("coded:ResolutionScope", "str", "str"),
        2: ("u4", "str", "str", "coded:TypeDefOrRef", "table:4", "table:6"),
        3: ("table:4",),
        4: ("u2", "str", "blob"),
        5: ("table:6",),
        6: ("u4", "u2", "u2", "str", "blob", "table:8"),
        7: ("table:8",),
        8: ("u2", "u2", "str"),
        9: ("table:2", "coded:TypeDefOrRef"),
        10: ("coded:MemberRefParent", "str", "blob"),
        11: ("u2", "coded:HasConstant", "blob"),
        12: ("coded:HasCustomAttribute", "coded:CustomAttributeType", "blob"),
        13: ("coded:HasFieldMarshal", "blob"),
        14: ("u2", "coded:HasDeclSecurity", "blob"),
        15: ("u2", "u4", "table:2"),
        16: ("u4", "table:4"),
        17: ("blob",),
        18: ("table:2", "table:20"),
        19: ("table:20",),
        20: ("u2", "str", "coded:TypeDefOrRef"),
        21: ("table:2", "table:23"),
        22: ("table:23",),
        23: ("u2", "str", "blob"),
        24: ("u2", "table:6", "coded:HasSemantics"),
        25: ("table:2", "coded:MethodDefOrRef", "coded:MethodDefOrRef"),
        26: ("str",),
        27: ("blob",),
        28: ("u2", "coded:MemberForwarded", "str", "table:26"),
        29: ("u4", "table:4"),
        30: ("u4", "u4"),
        31: ("u4",),
        32: ("u4", "u2", "u2", "u2", "u2", "u4", "blob", "str", "str"),
        33: ("u4",),
        34: ("u4", "u4", "u4"),
        35: ("u2", "u2", "u2", "u2", "u4", "blob", "str", "str", "blob"),
        36: ("u4", "table:35"),
        37: ("u4", "u4", "u4", "table:35"),
        38: ("u4", "str", "blob"),
        39: ("u4", "u4", "str", "str", "coded:Implementation"),
        40: ("u4", "u4", "str", "coded:Implementation"),
        41: ("table:2", "table:2"),
        42: ("u2", "u2", "coded:TypeOrMethodDef", "str"),
        43: ("coded:MethodDefOrRef", "blob"),
        44: ("table:42", "coded:TypeDefOrRef"),
    }

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"pe_metadata.json"})

    def can_analyze(self, data: bytes) -> bool:
        """Check if data looks like a PE file."""
        if len(data) < 64:
            return False
        # Check for MZ header
        if data[:2] != b"MZ":
            return False
        # Check for PE signature at offset from e_lfanew
        try:
            e_lfanew = struct.unpack("<I", data[60:64])[0]
            if e_lfanew + 24 > len(data):
                return False
            return data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
        except Exception:
            return False

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Extract PE metadata without executing the file."""
        metadata = self._extract_pe_metadata(data)
        if metadata:
            import json

            resource_artifacts: List[Tuple[str, bytes]] = []
            stored_hashes: set[str] = set()
            stored_bytes = 0
            dotnet = metadata.get("dotnet")
            if isinstance(dotnet, dict):
                resources = dotnet.get("manifest_resources")
                if isinstance(resources, list):
                    for record in resources:
                        if not isinstance(record, dict):
                            continue
                        embedded = record.get("embedded_data")
                        if not isinstance(embedded, dict):
                            continue
                        embedded["artifact"] = None
                        embedded["stored"] = False
                        offset = embedded.get("file_offset")
                        size = embedded.get("size")
                        if (
                            embedded.get("range_valid") is not True
                            or not isinstance(offset, int)
                            or not isinstance(size, int)
                            or size < 0
                            or size > self._MAX_DOTNET_RESOURCE_ITEM_SIZE
                            or stored_bytes + size
                            > self._MAX_DOTNET_RESOURCE_TOTAL_SIZE
                            or len(resource_artifacts)
                            >= self._MAX_DOTNET_RESOURCE_ARTIFACTS
                        ):
                            continue
                        payload = data[offset : offset + size]
                        digest = sha256(payload).hexdigest()
                        if digest in stored_hashes:
                            embedded["duplicate_sha256"] = digest
                            continue
                        stored_hashes.add(digest)
                        raw_name = str(record.get("name") or "resource.bin")
                        safe_name = (
                            "".join(
                                character
                                for character in raw_name.replace("\\", "/").rsplit(
                                    "/", 1
                                )[-1]
                                if character.isalnum() or character in "._-"
                            )[:120]
                            or "resource.bin"
                        )
                        artifact_name = (
                            f"dotnet_resource_{len(resource_artifacts) + 1:03d}_"
                            f"{safe_name}"
                        )
                        embedded["artifact"] = artifact_name
                        embedded["stored"] = True
                        stored_bytes += size
                        resource_artifacts.append((artifact_name, payload))
            metadata_json = json.dumps(metadata, indent=2).encode("utf-8")
            return [("pe_metadata.json", metadata_json), *resource_artifacts]
        return []

    @classmethod
    def _dotnet_index_width(
        cls,
        token: str,
        row_counts: Dict[int, int],
        heap_sizes: int,
    ) -> int:
        if token == "str":
            return 4 if heap_sizes & 0x01 else 2
        if token == "guid":
            return 4 if heap_sizes & 0x02 else 2
        if token == "blob":
            return 4 if heap_sizes & 0x04 else 2
        if token.startswith("table:"):
            table = int(token.partition(":")[2])
            return 4 if row_counts.get(table, 0) >= 1 << 16 else 2
        if token.startswith("coded:"):
            name = token.partition(":")[2]
            tag_bits, tables = cls._DOTNET_CODED_INDEXES[name]
            maximum = max((row_counts.get(table, 0) for table in tables), default=0)
            return 4 if maximum >= 1 << (16 - tag_bits) else 2
        return 4 if token == "u4" else 2

    @classmethod
    def _dotnet_row_size(
        cls,
        table: int,
        row_counts: Dict[int, int],
        heap_sizes: int,
    ) -> int | None:
        schema = cls._DOTNET_TABLE_SCHEMAS.get(table)
        if schema is None:
            return None
        return sum(
            cls._dotnet_index_width(token, row_counts, heap_sizes) for token in schema
        )

    @staticmethod
    def _dotnet_blob(
        data: bytes,
        blob_range: tuple[int, int] | None,
        index: int,
        *,
        maximum: int = 4096,
    ) -> bytes | None:
        if blob_range is None or index <= 0:
            return b"" if index == 0 else None
        blob_at, blob_size = blob_range
        if index >= blob_size:
            return None
        cursor = blob_at + index
        end = blob_at + blob_size
        if cursor >= end:
            return None
        first = data[cursor]
        if first & 0x80 == 0:
            length, prefix = first, 1
        elif first & 0xC0 == 0x80 and cursor + 2 <= end:
            length = ((first & 0x3F) << 8) | data[cursor + 1]
            prefix = 2
        elif first & 0xE0 == 0xC0 and cursor + 4 <= end:
            length = (
                ((first & 0x1F) << 24)
                | (data[cursor + 1] << 16)
                | (data[cursor + 2] << 8)
                | data[cursor + 3]
            )
            prefix = 4
        else:
            return None
        if length > maximum or cursor + prefix + length > end:
            return None
        return data[cursor + prefix : cursor + prefix + length]

    def _parse_dotnet_metadata(
        self,
        data: bytes,
        rva_offset: Any,
        clr_rva: int,
        clr_size: int,
    ) -> Dict[str, Any]:
        """Parse bounded CLI and ECMA-335 metadata-root structure."""

        result: Dict[str, Any] = {
            "present": True,
            "valid": False,
            "anomalies": [],
        }
        clr_at = rva_offset(clr_rva)
        if clr_at is None or clr_size < 24 or clr_at + 24 > len(data):
            result["anomalies"].append("invalid_clr_header_range")
            return result
        header_size, major, minor, metadata_rva, metadata_size, flags, entry = (
            struct.unpack_from("<IHHIIII", data, clr_at)
        )
        result.update(
            {
                "header_size": header_size,
                "runtime_version": f"{major}.{minor}",
                "metadata_rva": f"0x{metadata_rva:08x}",
                "metadata_size": metadata_size,
                "flags": {
                    "raw": f"0x{flags:08x}",
                    "il_only": bool(flags & 0x00000001),
                    "requires_32_bit": bool(flags & 0x00000002),
                    "strong_name_signed": bool(flags & 0x00000008),
                    "native_entry_point": bool(flags & 0x00000010),
                    "prefers_32_bit": bool(flags & 0x00020000),
                },
                "entry_point": {
                    "kind": "native_rva" if flags & 0x00000010 else "metadata_token",
                    "value": f"0x{entry:08x}",
                },
            }
        )
        if header_size < 72 or header_size > clr_size:
            result["anomalies"].append("invalid_clr_header_size")

        managed_resources_at: int | None = None
        managed_resources_size = 0
        if clr_at + 32 <= len(data) and clr_size >= 32:
            resources_rva, managed_resources_size = struct.unpack_from(
                "<II", data, clr_at + 24
            )
            managed_resources_at = (
                rva_offset(resources_rva) if managed_resources_size else None
            )
            result["managed_resource_directory"] = {
                "present": bool(managed_resources_size),
                "rva": f"0x{resources_rva:08x}",
                "size": managed_resources_size,
                "range_valid": bool(
                    managed_resources_at is not None
                    and managed_resources_size <= len(data) - managed_resources_at
                ),
            }

        if clr_at + 40 <= len(data) and clr_size >= 40:
            strong_name_rva, strong_name_size = struct.unpack_from(
                "<II", data, clr_at + 32
            )
            strong_name_at = rva_offset(strong_name_rva) if strong_name_size else None
            result["strong_name_signature"] = {
                "present": bool(strong_name_size),
                "rva": f"0x{strong_name_rva:08x}",
                "size": strong_name_size,
                "range_valid": bool(
                    strong_name_at is not None
                    and strong_name_size <= len(data) - strong_name_at
                ),
            }

        metadata_at = rva_offset(metadata_rva)
        if (
            metadata_at is None
            or metadata_size < 20
            or metadata_size > self._MAX_DOTNET_METADATA_SIZE
            or metadata_size > len(data) - metadata_at
        ):
            result["anomalies"].append("invalid_metadata_root_range")
            return result
        metadata_end = metadata_at + metadata_size
        if data[metadata_at : metadata_at + 4] != b"BSJB":
            result["anomalies"].append("invalid_metadata_signature")
            return result

        metadata_major, metadata_minor = struct.unpack_from(
            "<HH", data, metadata_at + 4
        )
        version_length = struct.unpack_from("<I", data, metadata_at + 12)[0]
        if version_length > 1024 or metadata_at + 16 + version_length > metadata_end:
            result["anomalies"].append("invalid_metadata_version_range")
            return result
        version_bytes = data[metadata_at + 16 : metadata_at + 16 + version_length]
        version = version_bytes.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        cursor = metadata_at + ((16 + version_length + 3) & ~3)
        if cursor + 4 > metadata_end:
            result["anomalies"].append("truncated_metadata_stream_count")
            return result
        metadata_flags, stream_count = struct.unpack_from("<HH", data, cursor)
        cursor += 4
        if stream_count > self._MAX_DOTNET_STREAMS:
            result["anomalies"].append("excessive_metadata_stream_count")
            return result

        streams: list[Dict[str, Any]] = []
        stream_ranges: Dict[str, tuple[int, int]] = {}
        seen_names: set[str] = set()
        for _ in range(stream_count):
            if cursor + 9 > metadata_end:
                result["anomalies"].append("truncated_metadata_stream_header")
                return result
            relative_offset, size = struct.unpack_from("<II", data, cursor)
            name_start = cursor + 8
            name_end = data.find(
                b"\x00", name_start, min(metadata_end, name_start + 32)
            )
            if name_end < 0:
                result["anomalies"].append("unterminated_metadata_stream_name")
                return result
            name = data[name_start:name_end].decode("ascii", errors="replace")
            cursor = metadata_at + ((name_end + 1 - metadata_at + 3) & ~3)
            range_valid = bool(
                relative_offset <= metadata_size
                and size <= metadata_size - relative_offset
            )
            if name in seen_names:
                result["anomalies"].append(f"duplicate_metadata_stream:{name}")
            seen_names.add(name)
            streams.append(
                {
                    "name": name,
                    "offset": relative_offset,
                    "size": size,
                    "range_valid": range_valid,
                }
            )
            if range_valid and name not in stream_ranges:
                stream_ranges[name] = (metadata_at + relative_offset, size)

        table_rows: Dict[str, int] = {}
        row_counts: Dict[int, int] = {}
        module: Dict[str, Any] | None = None
        assembly: Dict[str, Any] | None = None
        assembly_references: list[Dict[str, Any]] = []
        manifest_resources: list[Dict[str, Any]] = []
        string_values: list[str] = []
        strings_range = stream_ranges.get("#Strings")
        if strings_range is not None:
            strings_at, strings_size = strings_range
            strings_data = data[
                strings_at : strings_at
                + min(strings_size, self._MAX_DOTNET_STRING_BYTES)
            ]
            position = 1 if strings_data.startswith(b"\x00") else 0
            while (
                position < len(strings_data)
                and len(string_values) < self._MAX_DOTNET_STRINGS
            ):
                end = strings_data.find(b"\x00", position)
                if end < 0:
                    break
                if end > position:
                    value = strings_data[position:end].decode("utf-8", errors="replace")
                    if value:
                        string_values.append(value[:512])
                position = end + 1

        def heap_string(index: int) -> str | None:
            if strings_range is None or index <= 0:
                return None
            strings_at, strings_size = strings_range
            if index >= strings_size or strings_at + index >= metadata_end:
                return None
            start = strings_at + index
            end = data.find(b"\x00", start, min(strings_at + strings_size, start + 512))
            if end < 0:
                return None
            return data[start:end].decode("utf-8", errors="replace")

        table_range = stream_ranges.get("#~") or stream_ranges.get("#-")
        if table_range is not None:
            table_at, table_size = table_range
            if table_size < 24 or table_at + 24 > metadata_end:
                result["anomalies"].append("truncated_metadata_tables_header")
            else:
                heap_sizes = data[table_at + 6]
                valid_mask = struct.unpack_from("<Q", data, table_at + 8)[0]
                row_cursor = table_at + 24
                present_indexes = [
                    index for index in range(64) if valid_mask & (1 << index)
                ]
                if row_cursor + 4 * len(present_indexes) > table_at + table_size:
                    result["anomalies"].append("truncated_metadata_row_counts")
                else:
                    for index in present_indexes:
                        rows = struct.unpack_from("<I", data, row_cursor)[0]
                        row_cursor += 4
                        name = (
                            self._DOTNET_TABLE_NAMES[index]
                            if index < len(self._DOTNET_TABLE_NAMES)
                            else f"Table{index}"
                        )
                        table_rows[name] = rows
                        row_counts[index] = rows

                    table_offsets: Dict[int, tuple[int, int]] = {}
                    table_cursor = row_cursor
                    table_end = table_at + table_size
                    for index in present_indexes:
                        row_size = self._dotnet_row_size(index, row_counts, heap_sizes)
                        if row_size is None:
                            result["anomalies"].append(
                                f"unsupported_metadata_table:{index}"
                            )
                            break
                        table_bytes = row_counts[index] * row_size
                        if table_bytes > table_end - table_cursor:
                            result["anomalies"].append(
                                f"truncated_metadata_table:{index}"
                            )
                            break
                        table_offsets[index] = (table_cursor, row_size)
                        table_cursor += table_bytes

                    string_width = 4 if heap_sizes & 0x01 else 2
                    guid_width = 4 if heap_sizes & 0x02 else 2
                    blob_width = 4 if heap_sizes & 0x04 else 2

                    def read_index(at: int, width: int) -> int:
                        return int.from_bytes(data[at : at + width], "little")

                    module_layout = table_offsets.get(0)
                    if module_layout is not None and row_counts.get(0, 0) > 0:
                        module_at, _ = module_layout
                        name_index = read_index(module_at + 2, string_width)
                        mvid_at = module_at + 2 + string_width
                        mvid_index = read_index(mvid_at, guid_width)
                        mvid: str | None = None
                        guid_range = stream_ranges.get("#GUID")
                        if guid_range is not None and mvid_index > 0:
                            guid_at, guid_size = guid_range
                            relative_guid = (mvid_index - 1) * 16
                            if relative_guid + 16 <= guid_size:
                                mvid = data[
                                    guid_at + relative_guid : guid_at
                                    + relative_guid
                                    + 16
                                ].hex()
                        module = {
                            "name": heap_string(name_index),
                            "mvid": mvid,
                            "mvid_index": mvid_index,
                        }

                    assembly_layout = table_offsets.get(32)
                    if assembly_layout is not None and row_counts.get(32, 0) > 0:
                        assembly_at, _ = assembly_layout
                        hash_algorithm = struct.unpack_from("<I", data, assembly_at)[0]
                        version_parts = struct.unpack_from(
                            "<HHHH", data, assembly_at + 4
                        )
                        assembly_flags = struct.unpack_from(
                            "<I", data, assembly_at + 12
                        )[0]
                        value_at = assembly_at + 16
                        public_key_index = read_index(value_at, blob_width)
                        value_at += blob_width
                        name_index = read_index(value_at, string_width)
                        value_at += string_width
                        culture_index = read_index(value_at, string_width)
                        public_key = self._dotnet_blob(
                            data,
                            stream_ranges.get("#Blob"),
                            public_key_index,
                        )
                        assembly_name = heap_string(name_index)
                        if assembly_name is None:
                            result["anomalies"].append("invalid_assembly_name_index")
                        if public_key_index and public_key is None:
                            result["anomalies"].append(
                                "invalid_assembly_public_key_index"
                            )
                        assembly = {
                            "name": assembly_name,
                            "version": ".".join(str(value) for value in version_parts),
                            "culture": heap_string(culture_index) or "neutral",
                            "flags": f"0x{assembly_flags:08x}",
                            "hash_algorithm": {
                                0: "none",
                                0x8003: "md5",
                                0x8004: "sha1",
                            }.get(hash_algorithm, f"0x{hash_algorithm:08x}"),
                            "public_key": None
                            if not public_key
                            else {
                                "size": len(public_key),
                                "sha256": sha256(public_key).hexdigest(),
                                "preview_hex": public_key[:32].hex(),
                            },
                        }

                    reference_layout = table_offsets.get(35)
                    if reference_layout is not None:
                        reference_at, reference_size = reference_layout
                        for row in range(
                            min(
                                row_counts.get(35, 0),
                                self._MAX_DOTNET_REFERENCES,
                            )
                        ):
                            at = reference_at + row * reference_size
                            version_parts = struct.unpack_from("<HHHH", data, at)
                            reference_flags = struct.unpack_from("<I", data, at + 8)[0]
                            value_at = at + 12
                            key_index = read_index(value_at, blob_width)
                            value_at += blob_width
                            name_index = read_index(value_at, string_width)
                            value_at += string_width
                            culture_index = read_index(value_at, string_width)
                            value_at += string_width
                            hash_index = read_index(value_at, blob_width)
                            key = self._dotnet_blob(
                                data, stream_ranges.get("#Blob"), key_index
                            )
                            reference_hash = self._dotnet_blob(
                                data, stream_ranges.get("#Blob"), hash_index
                            )
                            reference_name = heap_string(name_index)
                            if reference_name is None:
                                result["anomalies"].append(
                                    f"invalid_assembly_reference_name:{row + 1}"
                                )
                            if key_index and key is None:
                                result["anomalies"].append(
                                    f"invalid_assembly_reference_key:{row + 1}"
                                )
                            if hash_index and reference_hash is None:
                                result["anomalies"].append(
                                    f"invalid_assembly_reference_hash:{row + 1}"
                                )
                            assembly_references.append(
                                {
                                    "row": row + 1,
                                    "name": reference_name,
                                    "version": ".".join(
                                        str(value) for value in version_parts
                                    ),
                                    "culture": heap_string(culture_index) or "neutral",
                                    "flags": f"0x{reference_flags:08x}",
                                    "public_key_or_token": None
                                    if not key
                                    else key.hex(),
                                    "hash": None
                                    if not reference_hash
                                    else reference_hash.hex(),
                                }
                            )

                    resource_layout = table_offsets.get(40)
                    implementation_width = self._dotnet_index_width(
                        "coded:Implementation", row_counts, heap_sizes
                    )
                    if resource_layout is not None:
                        resource_at, resource_size = resource_layout
                        for row in range(
                            min(
                                row_counts.get(40, 0),
                                self._MAX_DOTNET_RESOURCES,
                            )
                        ):
                            at = resource_at + row * resource_size
                            offset, resource_flags = struct.unpack_from("<II", data, at)
                            name_index = read_index(at + 8, string_width)
                            implementation = read_index(
                                at + 8 + string_width,
                                implementation_width,
                            )
                            tag = implementation & 0x03
                            target_row = implementation >> 2
                            target_table = {
                                0: "File",
                                1: "AssemblyRef",
                                2: "ExportedType",
                            }.get(tag)
                            resolved_name = heap_string(name_index)
                            if resolved_name is None:
                                result["anomalies"].append(
                                    f"invalid_manifest_resource_name:{row + 1}"
                                )
                            record: Dict[str, Any] = {
                                "row": row + 1,
                                "name": resolved_name,
                                "offset": offset,
                                "visibility": "public"
                                if resource_flags & 0x01
                                else "private"
                                if resource_flags & 0x02
                                else "unspecified",
                                "implementation": "embedded"
                                if implementation == 0
                                else {
                                    "table": target_table or f"tag:{tag}",
                                    "row": target_row,
                                },
                            }
                            if implementation == 0:
                                payload_at = (
                                    managed_resources_at + offset
                                    if managed_resources_at is not None
                                    else None
                                )
                                if (
                                    payload_at is not None
                                    and offset <= managed_resources_size
                                    and payload_at + 4 <= len(data)
                                    and offset + 4 <= managed_resources_size
                                ):
                                    payload_size = struct.unpack_from(
                                        "<I", data, payload_at
                                    )[0]
                                    range_valid = bool(
                                        payload_size
                                        <= managed_resources_size - offset - 4
                                        and payload_size <= len(data) - payload_at - 4
                                    )
                                    record["embedded_data"] = {
                                        "size": payload_size,
                                        "file_offset": payload_at + 4,
                                        "range_valid": range_valid,
                                        "sha256": sha256(
                                            data[
                                                payload_at + 4 : payload_at
                                                + 4
                                                + payload_size
                                            ]
                                        ).hexdigest()
                                        if range_valid
                                        else None,
                                    }
                                    if not range_valid:
                                        result["anomalies"].append(
                                            f"invalid_manifest_resource_range:{row + 1}"
                                        )
                                else:
                                    record["embedded_data"] = {
                                        "size": None,
                                        "file_offset": None,
                                        "range_valid": False,
                                        "sha256": None,
                                    }
                                    result["anomalies"].append(
                                        f"invalid_manifest_resource_range:{row + 1}"
                                    )
                            manifest_resources.append(record)

        result.update(
            {
                "valid": not any(
                    anomaly.startswith(("invalid_", "truncated_", "unterminated_"))
                    for anomaly in result["anomalies"]
                ),
                "metadata_version": f"{metadata_major}.{metadata_minor}",
                "metadata_version_string": version[:256],
                "metadata_flags": f"0x{metadata_flags:04x}",
                "assembly": assembly,
                "assembly_reference_count": table_rows.get("AssemblyRef", 0),
                "assembly_references": assembly_references,
                "assembly_references_truncated": table_rows.get("AssemblyRef", 0)
                > len(assembly_references),
                "manifest_resource_count": table_rows.get("ManifestResource", 0),
                "manifest_resources": manifest_resources,
                "manifest_resources_truncated": table_rows.get("ManifestResource", 0)
                > len(manifest_resources),
                "module": module,
                "streams": streams,
                "string_heap_preview": string_values,
                "table_row_counts": table_rows,
            }
        )
        return result

    def _parse_installer_overlay(
        self, data: bytes, overlay_offset: int
    ) -> Dict[str, Any] | None:
        """Identify bounded, structurally validated installer data in a PE overlay."""

        overlay_offset = min(max(overlay_offset, 0), len(data))
        scan_end = min(len(data), overlay_offset + self._MAX_INSTALLER_SCAN)
        scanned = data[overlay_offset:scan_end]
        formats: list[Dict[str, Any]] = []

        search_at = 0
        for _ in range(8):
            signature_at = scanned.find(self._NSIS_SIGNATURE, search_at)
            if signature_at < 0:
                break
            search_at = signature_at + 1
            header_at = signature_at - 4
            if header_at < 0 or header_at + 28 > len(scanned):
                continue
            (
                flags,
                signature,
                magic_1,
                magic_2,
                magic_3,
                header_length,
                following_length,
            ) = struct.unpack_from("<7I", scanned, header_at)
            range_valid = bool(
                signature == 0xDEADBEEF
                and (magic_1, magic_2, magic_3) == (0x6C6C754E, 0x74666F73, 0x74736E49)
                and flags & ~0x0F == 0
                and header_length > 0
                and following_length >= 28
                and header_length <= following_length - 28
                and following_length <= len(scanned) - header_at
            )
            if not range_valid:
                continue
            formats.append(
                {
                    "family": "NSIS",
                    "offset": overlay_offset + header_at,
                    "header_length": header_length,
                    "following_data_length": following_length,
                    "range_valid": True,
                    "flags": {
                        "raw": f"0x{flags:08x}",
                        "uninstaller": bool(flags & 0x01),
                        "silent": bool(flags & 0x02),
                        "no_crc": bool(flags & 0x04),
                        "force_crc": bool(flags & 0x08),
                    },
                }
            )

        for match in list(self._INNO_SETUP_ID.finditer(scanned))[:8]:
            identifier = match.group(0).decode("ascii", errors="replace")
            formats.append(
                {
                    "family": "Inno Setup",
                    "offset": overlay_offset + match.start(),
                    "identifier": identifier,
                    "data_format_version": match.group(1).decode("ascii"),
                    "unicode": bool(match.group(2)),
                }
            )

        if not formats:
            return None
        formats.sort(key=lambda item: (int(item["offset"]), str(item["family"])))
        return {
            "overlay_offset": overlay_offset,
            "overlay_size": len(data) - overlay_offset,
            "scan_bytes": len(scanned),
            "scan_truncated": scan_end < len(data),
            "formats": formats,
        }

    def _extract_pe_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract key metadata from PE file."""
        try:
            # DOS header
            e_lfanew = struct.unpack("<I", data[60:64])[0]

            # PE signature offset
            pe_offset = e_lfanew

            # COFF header (after PE signature)
            coff_offset = pe_offset + 4

            if coff_offset + 20 > len(data):
                return None

            # Parse COFF header
            (
                machine,
                num_sections,
                time_date_stamp,
                ptr_to_sym_table,
                num_symbols,
                size_of_opt_header,
                characteristics,
            ) = struct.unpack("<HHIIIHH", data[coff_offset : coff_offset + 20])

            # Machine types
            machine_types = {
                0x014C: "x86",
                0x0200: "IA64",
                0x8664: "x64",
                0x01C0: "ARM",
                # 0x01C4 is IMAGE_FILE_MACHINE_ARMNT (32-bit ARM Thumb-2),
                # not ARM64 (0xAA64) — mislabeling it corrupts triage.
                0x01C4: "ARM Thumb-2",
                0xAA64: "ARM64",
            }

            # Optional header
            metadata = {
                "file_type": "PE",
                "machine_type": machine_types.get(
                    machine, f"Unknown (0x{machine:04x})"
                ),
                "num_sections": num_sections,
                "time_date_stamp": time_date_stamp,
                "characteristics": f"0x{characteristics:04x}",
                "has_optional_header": size_of_opt_header > 0,
            }

            if size_of_opt_header > 0:
                opt_offset = coff_offset + 20
                if opt_offset + 24 <= len(data):
                    # Parse optional header (first 24 bytes are common)
                    (
                        magic,
                        major_linker,
                        minor_linker,
                        size_of_code,
                        size_of_init_data,
                        size_of_uninit_data,
                        entry_point,
                        base_of_code,
                    ) = struct.unpack("<HBBIIIII", data[opt_offset : opt_offset + 24])

                    metadata.update(
                        {
                            "magic": "PE32+"
                            if magic == 0x20B
                            else "PE32"
                            if magic == 0x10B
                            else f"Unknown (0x{magic:04x})",
                            "entry_point": f"0x{entry_point:08x}",
                            "size_of_code": size_of_code,
                            "size_of_init_data": size_of_init_data,
                            "size_of_uninit_data": size_of_uninit_data,
                        }
                    )

                    # For PE32, image base is a 4-byte field at offset 28.
                    if magic == 0x10B and opt_offset + 32 <= len(data):
                        image_base = struct.unpack(
                            "<I", data[opt_offset + 28 : opt_offset + 32]
                        )[0]
                        metadata["image_base"] = f"0x{image_base:08x}"

                    # For PE32+, image base is an 8-byte field at offset 24.
                    elif magic == 0x20B and opt_offset + 32 <= len(data):
                        image_base = struct.unpack(
                            "<Q", data[opt_offset + 24 : opt_offset + 32]
                        )[0]
                        metadata["image_base"] = f"0x{image_base:016x}"

                    section_offset = opt_offset + size_of_opt_header
                    sections: list[dict[str, Any]] = []
                    raw_end = 0
                    entry_section = None
                    anomalies: list[str] = []
                    for index in range(min(num_sections, 96)):
                        at = section_offset + index * 40
                        if at + 40 > len(data):
                            anomalies.append("truncated_section_table")
                            break
                        name = (
                            data[at : at + 8]
                            .split(b"\x00", 1)[0]
                            .decode("ascii", errors="replace")
                        )
                        (
                            virtual_size,
                            virtual_address,
                            raw_size,
                            raw_pointer,
                            _relocations,
                            _line_numbers,
                            _relocation_count,
                            _line_count,
                            section_flags,
                        ) = struct.unpack("<IIIIIIHHI", data[at + 8 : at + 40])
                        raw = (
                            data[raw_pointer : raw_pointer + raw_size]
                            if raw_pointer <= len(data)
                            and raw_size <= len(data) - raw_pointer
                            else b""
                        )
                        executable = bool(section_flags & 0x20000000)
                        writable = bool(section_flags & 0x80000000)
                        if executable and writable:
                            anomalies.append(f"writable_executable_section:{name}")
                        section_entropy = round(entropy(raw), 4) if raw else 0.0
                        if executable and len(raw) >= 256 and section_entropy >= 7.2:
                            anomalies.append(f"high_entropy_executable_section:{name}")
                        if (
                            virtual_address
                            <= entry_point
                            < virtual_address + max(virtual_size, raw_size, 1)
                        ):
                            entry_section = name
                        raw_end = max(raw_end, raw_pointer + raw_size)
                        sections.append(
                            {
                                "name": name,
                                "virtual_address": f"0x{virtual_address:08x}",
                                "virtual_size": virtual_size,
                                "raw_offset": raw_pointer,
                                "raw_size": raw_size,
                                "entropy": section_entropy,
                                "executable": executable,
                                "writable": writable,
                                "characteristics": f"0x{section_flags:08x}",
                            }
                        )

                    def rva_offset(rva: int) -> int | None:
                        for section in sections:
                            start = int(str(section["virtual_address"]), 16)
                            span = max(
                                int(section["virtual_size"]),
                                int(section["raw_size"]),
                                1,
                            )
                            if start <= rva < start + span:
                                offset = int(section["raw_offset"]) + rva - start
                                return offset if offset < len(data) else None
                        return rva if 0 <= rva < len(data) else None

                    directories_at = 96 if magic == 0x10B else 112
                    imports: list[str] = []
                    signature = {"present": False, "offset": 0, "size": 0}
                    if opt_offset + directories_at + 40 <= min(
                        section_offset, len(data)
                    ):
                        import_rva, import_size = struct.unpack_from(
                            "<II", data, opt_offset + directories_at + 8
                        )
                        import_at = rva_offset(import_rva) if import_size else None
                        for descriptor_index in range(256):
                            if import_at is None:
                                break
                            descriptor = import_at + descriptor_index * 20
                            if descriptor + 20 > len(data):
                                break
                            values = struct.unpack_from("<IIIII", data, descriptor)
                            if not any(values):
                                break
                            name_at = rva_offset(values[3])
                            if name_at is None:
                                continue
                            end = data.find(
                                b"\x00", name_at, min(len(data), name_at + 512)
                            )
                            if end < 0:
                                continue
                            library = data[name_at:end].decode(
                                "ascii", errors="replace"
                            )
                            if library:
                                imports.append(library)
                        certificate_at, certificate_size = struct.unpack_from(
                            "<II", data, opt_offset + directories_at + 32
                        )
                        signature = {
                            "present": bool(
                                certificate_size
                                and certificate_at < len(data)
                                and certificate_size <= len(data) - certificate_at
                            ),
                            "offset": certificate_at,
                            "size": certificate_size,
                        }

                    number_of_directories_at = 92 if magic == 0x10B else 108
                    if opt_offset + number_of_directories_at + 4 <= min(
                        section_offset, len(data)
                    ):
                        directory_count = struct.unpack_from(
                            "<I", data, opt_offset + number_of_directories_at
                        )[0]
                        clr_directory_at = opt_offset + directories_at + 14 * 8
                        if directory_count > 14 and clr_directory_at + 8 <= min(
                            section_offset, len(data)
                        ):
                            clr_rva, clr_size = struct.unpack_from(
                                "<II", data, clr_directory_at
                            )
                            if clr_rva or clr_size:
                                metadata["dotnet"] = self._parse_dotnet_metadata(
                                    data, rva_offset, clr_rva, clr_size
                                )

                    metadata.update(
                        {
                            "entry_point_section": entry_section,
                            "sections": sections,
                            "imports": sorted(set(imports), key=str.lower),
                            "authenticode": signature,
                            "overlay_size": max(0, len(data) - raw_end)
                            if raw_end
                            else 0,
                            "anomalies": sorted(set(anomalies)),
                        }
                    )
                    installer = self._parse_installer_overlay(data, raw_end)
                    if installer is not None:
                        metadata["installer"] = installer

            return metadata

        except Exception as e:
            return {"error": f"Failed to parse PE metadata: {str(e)}"}

    @property
    def name(self) -> str:
        return "PE"


class ELFAnalyzer(Analyzer):
    """ELF (Executable and Linkable Format) file metadata analyzer."""

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"elf_metadata.json"})

    def can_analyze(self, data: bytes) -> bool:
        """Check if data looks like an ELF file."""
        if len(data) < 16:
            return False
        # Check for ELF magic number
        return data[:4] == b"\x7fELF"

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Extract ELF metadata without executing the file."""
        metadata = self._extract_elf_metadata(data)
        if metadata:
            # Return metadata as JSON string
            import json

            metadata_json = json.dumps(metadata, indent=2).encode("utf-8")
            return [("elf_metadata.json", metadata_json)]
        return []

    def _extract_elf_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract key metadata from ELF file."""
        try:
            if len(data) < 64:
                return None

            # Parse ELF header (64 bytes)
            # e_ident (16 bytes)
            ei_class, ei_data, _ei_version, ei_osabi = (
                data[4],
                data[5],
                data[6],
                data[7],
            )

            # Class types
            class_types = {1: "32-bit", 2: "64-bit"}

            # Data encodings
            data_encodings = {1: "Little endian", 2: "Big endian"}

            # OS/ABI types
            osabi_types = {
                0: "System V",
                1: "HP-UX",
                2: "NetBSD",
                3: "Linux",
                6: "Solaris",
                9: "FreeBSD",
                12: "OpenBSD",
            }

            # Endianness and word size depend on e_ident: ELF64 uses 8-byte
            # e_entry/e_phoff/e_shoff, ELF32 uses 4-byte; ei_data selects
            # little- (1) vs big-endian (2).
            endian = ">" if ei_data == 2 else "<"
            if ei_class == 2:  # 64-bit
                header_fmt = endian + "HHIQQQIHHHHHH"
            else:  # 32-bit (and fallback)
                header_fmt = endian + "HHIIIIIHHHHHH"
            header_size = struct.calcsize(header_fmt)
            if len(data) < 16 + header_size:
                return None

            # Rest of header
            (
                e_type,
                e_machine,
                e_version,
                e_entry,
                e_phoff,
                e_shoff,
                e_flags,
                e_ehsize,
                e_phentsize,
                e_phnum,
                e_shentsize,
                e_shnum,
                e_shstrndx,
            ) = struct.unpack(header_fmt, data[16 : 16 + header_size])

            # Object file types
            object_types = {
                1: "Relocatable",
                2: "Executable",
                3: "Shared object",
                4: "Core",
            }

            # Machine types
            machine_types = {
                0x02: "SPARC",
                0x03: "x86",
                0x08: "MIPS",
                0x14: "PowerPC",
                0x28: "ARM",
                0x32: "IA-64",
                0x3E: "x86-64",
                0xB7: "AArch64",
                0xF3: "RISC-V",
            }

            metadata = {
                "file_type": "ELF",
                "class": class_types.get(ei_class, f"Unknown ({ei_class})"),
                "data_encoding": data_encodings.get(ei_data, f"Unknown ({ei_data})"),
                "os_abi": osabi_types.get(ei_osabi, f"Unknown ({ei_osabi})"),
                "object_type": object_types.get(e_type, f"Unknown (0x{e_type:04x})"),
                "machine_type": machine_types.get(
                    e_machine, f"Unknown (0x{e_machine:04x})"
                ),
                "entry_point": f"0x{e_entry:016x}"
                if ei_class == 2
                else f"0x{e_entry:08x}",
                "program_headers_offset": e_phoff,
                "section_headers_offset": e_shoff,
                "num_program_headers": e_phnum,
                "num_section_headers": e_shnum,
                "flags": f"0x{e_flags:08x}",
            }

            sections: list[dict[str, Any]] = []
            anomalies: list[str] = []
            section_names = b""
            section_records: list[tuple[int, ...]] = []
            section_fmt = endian + ("IIQQQQIIQQ" if ei_class == 2 else "IIIIIIIIII")
            expected_section_size = struct.calcsize(section_fmt)
            if (
                e_shoff
                and e_shentsize >= expected_section_size
                and e_shnum <= 4096
                and e_shoff + e_shentsize * e_shnum <= len(data)
            ):
                for index in range(min(e_shnum, 256)):
                    at = e_shoff + index * e_shentsize
                    section_records.append(
                        struct.unpack(
                            section_fmt, data[at : at + expected_section_size]
                        )
                    )
                if 0 <= e_shstrndx < len(section_records):
                    names_record = section_records[e_shstrndx]
                    names_offset = names_record[4]
                    names_size = names_record[5]
                    if (
                        names_offset <= len(data)
                        and names_size <= len(data) - names_offset
                    ):
                        section_names = data[names_offset : names_offset + names_size]

            def section_name(offset: int) -> str:
                if offset < 0 or offset >= len(section_names):
                    return ""
                end = section_names.find(b"\x00", offset)
                if end < 0:
                    end = len(section_names)
                return section_names[offset:end].decode("utf-8", errors="replace")

            entry_section = None
            for record in section_records:
                name_at, section_type, section_flags, address, offset, size = record[:6]
                name = section_name(name_at)
                raw = (
                    data[offset : offset + size]
                    if offset <= len(data) and size <= len(data) - offset
                    else b""
                )
                writable = bool(section_flags & 0x1)
                executable = bool(section_flags & 0x4)
                section_entropy = round(entropy(raw), 4) if raw else 0.0
                if writable and executable:
                    anomalies.append(f"writable_executable_section:{name}")
                if executable and len(raw) >= 256 and section_entropy >= 7.2:
                    anomalies.append(f"high_entropy_executable_section:{name}")
                if address <= e_entry < address + max(size, 1):
                    entry_section = name
                sections.append(
                    {
                        "name": name,
                        "type": section_type,
                        "address": f"0x{address:x}",
                        "offset": offset,
                        "size": size,
                        "entropy": section_entropy,
                        "writable": writable,
                        "executable": executable,
                    }
                )

            interpreter = None
            program_fmt = endian + ("IIQQQQQQ" if ei_class == 2 else "IIIIIIII")
            expected_program_size = struct.calcsize(program_fmt)
            if (
                e_phoff
                and e_phentsize >= expected_program_size
                and e_phnum <= 4096
                and e_phoff + e_phentsize * e_phnum <= len(data)
            ):
                for index in range(min(e_phnum, 256)):
                    at = e_phoff + index * e_phentsize
                    record = struct.unpack(
                        program_fmt, data[at : at + expected_program_size]
                    )
                    program_type = record[0]
                    file_offset = record[2] if ei_class == 2 else record[1]
                    file_size = record[5] if ei_class == 2 else record[4]
                    if (
                        program_type == 3
                        and file_offset <= len(data)
                        and file_size <= len(data) - file_offset
                    ):
                        interpreter = (
                            data[file_offset : file_offset + min(file_size, 4096)]
                            .split(b"\x00", 1)[0]
                            .decode("utf-8", errors="replace")
                        )
                        break

            libraries = sorted(
                {
                    match.decode("ascii", errors="replace")
                    for match in re.findall(
                        rb"(?:lib[\w.+-]{1,128}\.so(?:\.[\w.+-]{1,64})*)",
                        data[: 32 * 1024 * 1024],
                    )
                }
            )[:256]
            if sections and not any(
                section["name"] == ".symtab" for section in sections
            ):
                anomalies.append("symbol_table_absent")
            metadata.update(
                {
                    "entry_point_section": entry_section,
                    "interpreter": interpreter,
                    "needed_libraries": libraries,
                    "sections": sections,
                    "anomalies": sorted(set(anomalies)),
                }
            )

            return metadata

        except Exception as e:
            return {"error": f"Failed to parse ELF metadata: {str(e)}"}

    @property
    def name(self) -> str:
        return "ELF"
