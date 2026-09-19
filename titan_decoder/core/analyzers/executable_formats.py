"""Bounded structural analyzers for additional executable formats."""

from __future__ import annotations

import binascii
import json
import struct
from typing import Any
import uuid

from .base import Analyzer, bounded_summary
from ...utils.helpers import entropy


class MachOAnalyzer(Analyzer):
    """Parse thin 32/64-bit Mach-O headers, load commands, and sections."""

    _MAGICS = {
        b"\xce\xfa\xed\xfe": ("<", 32),
        b"\xcf\xfa\xed\xfe": ("<", 64),
        b"\xfe\xed\xfa\xce": (">", 32),
        b"\xfe\xed\xfa\xcf": (">", 64),
    }
    _CPU_TYPES = {
        7: "x86",
        0x01000007: "x86_64",
        12: "arm",
        0x0100000C: "arm64",
        18: "powerpc",
        0x01000012: "powerpc64",
    }
    _FILE_TYPES = {1: "object", 2: "executable", 6: "dylib", 8: "bundle"}
    _DYLIB_COMMANDS = {0xC, 0x18, 0x1F, 0x80000018, 0x8000001F}
    _MAX_COMMANDS = 2048
    _MAX_SECTIONS = 1024

    @property
    def name(self) -> str:
        return "Mach-O"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"macho_metadata.json"})

    def can_analyze(self, data: bytes) -> bool:
        return len(data) >= 28 and data[:4] in self._MAGICS

    @staticmethod
    def _cstring(raw: bytes) -> str:
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        metadata = self._parse(data)
        if metadata is None:
            return []
        return [("macho_metadata.json", json.dumps(metadata, indent=2).encode())]

    def _parse(self, data: bytes) -> dict[str, Any] | None:
        layout = self._MAGICS.get(data[:4])
        if layout is None:
            return None
        endian, bits = layout
        header_size = 32 if bits == 64 else 28
        if len(data) < header_size:
            return None
        cpu_type, cpu_subtype, file_type, ncmds, commands_size, flags = (
            struct.unpack_from(f"{endian}IIIIII", data, 4)
        )
        if ncmds > self._MAX_COMMANDS or commands_size > len(data) - header_size:
            return None
        commands_end = header_size + commands_size
        cursor = header_size
        sections: list[dict[str, Any]] = []
        dylibs: list[str] = []
        entry_offset: int | None = None
        uuid: str | None = None
        anomalies: list[str] = []
        for _ in range(ncmds):
            if cursor + 8 > commands_end:
                return None
            command, command_size = struct.unpack_from(f"{endian}II", data, cursor)
            if command_size < 8 or command_size > commands_end - cursor:
                return None
            if command in (1, 0x19):
                is_64 = command == 0x19
                segment_header = 72 if is_64 else 56
                section_size = 80 if is_64 else 68
                if command_size < segment_header:
                    return None
                nsects_at = cursor + (64 if is_64 else 48)
                nsects = struct.unpack_from(f"{endian}I", data, nsects_at)[0]
                if nsects > self._MAX_SECTIONS - len(sections):
                    return None
                if segment_header + nsects * section_size > command_size:
                    return None
                for index in range(nsects):
                    at = cursor + segment_header + index * section_size
                    section_name = self._cstring(data[at : at + 16])
                    segment_name = self._cstring(data[at + 16 : at + 32])
                    if is_64:
                        address, size, offset, _align, _reloc, _nreloc, sec_flags = (
                            struct.unpack_from(f"{endian}QQIIIII", data, at + 32)
                        )
                    else:
                        address, size, offset, _align, _reloc, _nreloc, sec_flags = (
                            struct.unpack_from(f"{endian}IIIIIII", data, at + 32)
                        )
                    raw = (
                        data[offset : offset + size]
                        if offset <= len(data) and size <= len(data) - offset
                        else b""
                    )
                    if size and not raw:
                        anomalies.append(
                            f"invalid_section_range:{segment_name},{section_name}"
                        )
                    sections.append(
                        {
                            "segment": segment_name,
                            "name": section_name,
                            "address": f"0x{address:x}",
                            "offset": offset,
                            "size": size,
                            "entropy": round(entropy(raw), 4) if raw else 0.0,
                            "flags": f"0x{sec_flags:08x}",
                        }
                    )
            elif command in self._DYLIB_COMMANDS and command_size >= 24:
                name_offset = struct.unpack_from(f"{endian}I", data, cursor + 8)[0]
                if 24 <= name_offset < command_size:
                    name = self._cstring(
                        data[cursor + name_offset : cursor + command_size]
                    )
                    if name:
                        dylibs.append(name)
            elif command == 0x80000028 and command_size >= 24:
                entry_offset = struct.unpack_from(f"{endian}Q", data, cursor + 8)[0]
            elif command == 0x1B and command_size >= 24:
                raw_uuid = data[cursor + 8 : cursor + 24].hex()
                uuid = "-".join(
                    (
                        raw_uuid[:8],
                        raw_uuid[8:12],
                        raw_uuid[12:16],
                        raw_uuid[16:20],
                        raw_uuid[20:],
                    )
                )
            cursor += command_size
        if cursor != commands_end:
            anomalies.append("load_command_padding")
        return {
            "file_type": "Mach-O",
            "bits": bits,
            "endianness": "little" if endian == "<" else "big",
            "cpu_type": self._CPU_TYPES.get(cpu_type, f"unknown:0x{cpu_type:08x}"),
            "cpu_subtype": f"0x{cpu_subtype:08x}",
            "macho_type": self._FILE_TYPES.get(file_type, f"unknown:{file_type}"),
            "flags": f"0x{flags:08x}",
            "load_command_count": ncmds,
            "entry_offset": entry_offset,
            "uuid": uuid,
            "dylibs": sorted(set(dylibs), key=str.lower),
            "sections": sections,
            "anomalies": sorted(set(anomalies)),
        }


class DexAnalyzer(Analyzer):
    """Parse DEX headers and a bounded subset of the string table."""

    _MAX_TABLE_ITEMS = 1_000_000
    _MAX_STRINGS = 4096
    _MAX_STRING_BYTES = 4096
    _MAX_TOTAL_STRING_BYTES = 2 * 1024 * 1024

    @property
    def name(self) -> str:
        return "DEX"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"dex_metadata.json"})

    def can_analyze(self, data: bytes) -> bool:
        return len(data) >= 112 and data[:4] == b"dex\n" and data[7] == 0

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        parsed = self._parse(data)
        if parsed is None:
            return []
        metadata, strings = parsed
        artifacts = [("dex_metadata.json", json.dumps(metadata, indent=2).encode())]
        if strings:
            artifacts.append(("dex_strings.txt", "\n".join(strings).encode("utf-8")))
        return artifacts

    @staticmethod
    def _uleb128(data: bytes, offset: int) -> tuple[int, int] | None:
        value = 0
        for index in range(5):
            if offset + index >= len(data):
                return None
            byte = data[offset + index]
            value |= (byte & 0x7F) << (index * 7)
            if not byte & 0x80:
                return value, offset + index + 1
        return None

    def _parse(self, data: bytes) -> tuple[dict[str, Any], list[str]] | None:
        if not self.can_analyze(data):
            return None
        version = data[4:7].decode("ascii", errors="replace")
        file_size, header_size, endian_tag = struct.unpack_from("<III", data, 32)
        if (
            file_size < 112
            or file_size > len(data)
            or header_size != 112
            or endian_tag != 0x12345678
        ):
            return None
        table_names = ("string", "type", "proto", "field", "method", "class")
        tables: dict[str, dict[str, int]] = {}
        for index, name in enumerate(table_names):
            count, offset = struct.unpack_from("<II", data, 56 + index * 8)
            if count > self._MAX_TABLE_ITEMS or (
                count and not 112 <= offset < file_size
            ):
                return None
            tables[name] = {"count": count, "offset": offset}
        string_count = tables["string"]["count"]
        string_offset = tables["string"]["offset"]
        if string_count and (string_count > (file_size - string_offset) // 4):
            return None
        strings: list[str] = []
        total = 0
        for index in range(min(string_count, self._MAX_STRINGS)):
            item_offset = struct.unpack_from("<I", data, string_offset + index * 4)[0]
            prefix = self._uleb128(data, item_offset)
            if prefix is None:
                continue
            _utf16_length, start = prefix
            end = data.find(
                b"\x00", start, min(file_size, start + self._MAX_STRING_BYTES + 1)
            )
            if end < 0:
                continue
            raw = data[start:end]
            total += len(raw)
            if total > self._MAX_TOTAL_STRING_BYTES:
                break
            text = raw.decode("utf-8", errors="replace").strip()
            if text:
                strings.append(text)
        metadata = {
            "file_type": "DEX",
            "version": version,
            "file_size": file_size,
            "checksum_adler32": f"0x{struct.unpack_from('<I', data, 8)[0]:08x}",
            "signature_sha1": data[12:32].hex(),
            "tables": tables,
            "strings_emitted": len(strings),
            "strings_truncated": string_count > len(strings),
        }
        return metadata, strings


class VirtualDiskAnalyzer(Analyzer):
    """Bounded, read-only structural inspection for VHD and VHDX images."""

    _VHD_COOKIE = b"conectix"
    _VHDX_SIGNATURE = b"vhdxfile"
    _VHD_TYPES = {2: "fixed", 3: "dynamic", 4: "differencing"}
    _VHDX_REGIONS = {
        "2dc27766-f623-4200-9d64-115e9bfd4a08": "bat",
        "8b7ca206-4790-4b9a-b8fe-575f050f886e": "metadata",
    }
    _VHDX_METADATA = {
        "caa16737-fa36-4d43-b3b6-33f0aa44e76b": "file_parameters",
        "2fa54224-cd1b-4876-b211-5dbed83bf4b8": "virtual_disk_size",
        "beca12ab-b2e6-4523-93ef-c309e000c746": "virtual_disk_id",
        "8141bf1d-a96f-4709-ba47-f233a8faab5f": "logical_sector_size",
        "cda348c7-445d-4471-9cc9-e9885251c556": "physical_sector_size",
        "a8d35f2d-b30b-454d-abf7-d3d84834ab0c": "parent_locator",
    }

    def __init__(self, config: dict[str, Any] | None = None):
        config = config or {}
        self.max_artifacts = min(
            max(int(config.get("max_structured_artifacts", 32)), 0), 128
        )
        self.max_total = min(
            max(int(config.get("max_structured_total_size", 16 << 20)), 0),
            64 << 20,
        )
        self.max_item = min(
            max(int(config.get("max_structured_artifact_size", 4 << 20)), 0),
            16 << 20,
        )

    @property
    def name(self) -> str:
        return "VirtualDisk"

    @property
    def metadata_artifact_names(self) -> frozenset:
        return frozenset({"virtual_disk_metadata.json"})

    def can_analyze(self, data: bytes) -> bool:
        return data.startswith(self._VHDX_SIGNATURE) or (
            len(data) >= 512
            and (data[-512:-504] == self._VHD_COOKIE or data[:8] == self._VHD_COOKIE)
        )

    def analyze(self, data: bytes) -> list[tuple[str, bytes]]:
        if data.startswith(self._VHDX_SIGNATURE):
            metadata, candidates = self._parse_vhdx(data)
            vhdx_artifacts: list[tuple[str, bytes]] = []
            total = 0
            stored_names = set()
            for name, content in candidates:
                if (
                    len(vhdx_artifacts) >= self.max_artifacts
                    or len(content) > self.max_item
                    or total + len(content) > self.max_total
                ):
                    continue
                vhdx_artifacts.append((name, content))
                stored_names.add(name)
                total += len(content)
            metadata["artifacts"] = [
                {
                    "name": name,
                    "size": len(content),
                    "stored": name in stored_names,
                }
                for name, content in candidates
            ]
            return self._with_metadata(metadata, vhdx_artifacts, total)

        footer = self._find_vhd_footer(data)
        if footer is None:
            return []
        metadata, footer_valid = self._parse_vhd_footer(footer, len(data))
        artifacts: list[tuple[str, bytes]] = []
        partitions: list[dict[str, Any]] = []
        partition_table: dict[str, Any] | None = None
        total = 0
        if footer_valid and metadata["disk_type"] == "fixed":
            disk_size = int(metadata["current_size"])
            disk_data = data[:disk_size]
            partition_table, partitions, extracted = self._partition_table(disk_data)
            for name, content in extracted:
                if (
                    len(artifacts) >= self.max_artifacts
                    or len(content) > self.max_item
                    or total + len(content) > self.max_total
                ):
                    break
                artifacts.append((name, content))
                total += len(content)
        metadata["partitions"] = partitions
        metadata["partition_table"] = partition_table
        metadata["partitions_extracted"] = len(artifacts)
        return self._with_metadata(metadata, artifacts, total)

    def _with_metadata(
        self,
        metadata: dict[str, Any],
        artifacts: list[tuple[str, bytes]],
        total: int,
    ) -> list[tuple[str, bytes]]:
        """Emit the metadata record within the same budget as the artifacts.

        The record used to be serialized straight into the returned list: not
        truncated to ``max_item`` and not counted against ``max_total``, even
        though its ``partitions`` and ``artifacts`` lists are derived from the
        input. It is the analyzer's account of what was found, so it takes
        priority over extracted content when the budget is tight.
        """
        # Bounded by the total budget, not ``max_item``: that knob caps each
        # *extracted* artifact, and callers lower it to constrain partition
        # extraction while still expecting the full account of what was found.
        encoded = bounded_summary(metadata, self.max_total)
        if encoded is None:
            return artifacts
        while artifacts and total + len(encoded) > self.max_total:
            total -= len(artifacts.pop()[1])
        if total + len(encoded) > self.max_total:
            return artifacts
        return [("virtual_disk_metadata.json", encoded), *artifacts]

    @staticmethod
    def _vhd_checksum(footer: bytes) -> int:
        prepared = footer[:64] + b"\x00\x00\x00\x00" + footer[68:512]
        return (~sum(prepared)) & 0xFFFFFFFF

    def _find_vhd_footer(self, data: bytes) -> bytes | None:
        candidates = []
        if len(data) >= 512:
            candidates.append(data[-512:])
            candidates.append(data[:512])
        for footer in candidates:
            if footer.startswith(self._VHD_COOKIE):
                return footer
        return None

    def _parse_vhd_footer(
        self, footer: bytes, file_size: int
    ) -> tuple[dict[str, Any], bool]:
        features, version = struct.unpack_from(">II", footer, 8)
        data_offset = struct.unpack_from(">Q", footer, 16)[0]
        timestamp = struct.unpack_from(">I", footer, 24)[0]
        creator_version = struct.unpack_from(">I", footer, 32)[0]
        original_size, current_size = struct.unpack_from(">QQ", footer, 40)
        geometry, disk_type_value, stored_checksum = struct.unpack_from(
            ">III", footer, 56
        )
        checksum_valid = self._vhd_checksum(footer) == stored_checksum
        disk_type = self._VHD_TYPES.get(disk_type_value, "unknown")
        anomalies = []
        if version != 0x00010000:
            anomalies.append("invalid_format_version")
        if not checksum_valid:
            anomalies.append("invalid_footer_checksum")
        if disk_type == "unknown":
            anomalies.append("invalid_disk_type")
        if current_size == 0 or current_size % 512:
            anomalies.append("invalid_current_size")
        if disk_type == "fixed" and current_size > max(0, file_size - 512):
            anomalies.append("fixed_disk_range_out_of_bounds")
        valid = not anomalies
        metadata = {
            "file_type": "VHD",
            "footer_valid": valid,
            "checksum_valid": checksum_valid,
            "features": f"0x{features:08x}",
            "format_version": f"0x{version:08x}",
            "data_offset": data_offset,
            "timestamp_seconds_since_2000": timestamp,
            "creator_application": footer[28:32].decode("ascii", errors="replace"),
            "creator_version": f"0x{creator_version:08x}",
            "creator_host_os": footer[36:40].decode("ascii", errors="replace"),
            "original_size": original_size,
            "current_size": current_size,
            "geometry": {
                "cylinders": geometry >> 16,
                "heads": (geometry >> 8) & 0xFF,
                "sectors_per_track": geometry & 0xFF,
            },
            "disk_type": disk_type,
            "disk_type_value": disk_type_value,
            "unique_id": str(uuid.UUID(bytes=footer[68:84])),
            "saved_state": bool(footer[84]),
            "anomalies": anomalies,
            "execution_performed": False,
        }
        return metadata, valid

    def _partition_table(
        self, disk_data: bytes
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[tuple[str, bytes]]]:
        if len(disk_data) < 512 or disk_data[510:512] != b"\x55\xaa":
            return (
                {
                    "scheme": None,
                    "valid": False,
                    "anomalies": ["missing_mbr_signature"],
                },
                [],
                [],
            )
        if len(disk_data) >= 1024 and disk_data[512:520] == b"EFI PART":
            return self._gpt_partitions(disk_data)
        partitions = []
        extracted = []
        for slot in range(4):
            entry = disk_data[446 + slot * 16 : 462 + slot * 16]
            partition_type = entry[4]
            start_lba, sector_count = struct.unpack_from("<II", entry, 8)
            if partition_type == 0 or sector_count == 0:
                continue
            offset = start_lba * 512
            size = sector_count * 512
            range_valid = offset >= 512 and offset + size <= len(disk_data)
            partitions.append(
                {
                    "slot": slot + 1,
                    "bootable": entry[0] == 0x80,
                    "type": f"0x{partition_type:02x}",
                    "start_lba": start_lba,
                    "sector_count": sector_count,
                    "offset": offset,
                    "size": size,
                    "range_valid": range_valid,
                }
            )
            if range_valid and size <= self.max_item:
                extracted.append(
                    (
                        f"disk_partition_{slot + 1:03d}.bin",
                        disk_data[offset : offset + size],
                    )
                )
        return {"scheme": "MBR", "valid": True, "anomalies": []}, partitions, extracted

    def _gpt_partitions(
        self, disk_data: bytes
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[tuple[str, bytes]]]:
        header = disk_data[512:1024]
        revision, header_size, stored_header_crc, reserved = struct.unpack_from(
            "<IIII", header, 8
        )
        my_lba, alternate_lba, first_usable, last_usable = struct.unpack_from(
            "<QQQQ", header, 24
        )
        entry_lba = struct.unpack_from("<Q", header, 72)[0]
        entry_count, entry_size, stored_entries_crc = struct.unpack_from(
            "<III", header, 80
        )
        total_lbas = len(disk_data) // 512
        anomalies = []
        if revision != 0x00010000:
            anomalies.append("invalid_gpt_revision")
        if not 92 <= header_size <= 512:
            anomalies.append("invalid_gpt_header_size")
            header_crc_valid = False
        else:
            prepared = bytearray(header[:header_size])
            prepared[16:20] = b"\x00" * 4
            header_crc_valid = (
                binascii.crc32(prepared) & 0xFFFFFFFF
            ) == stored_header_crc
            if not header_crc_valid:
                anomalies.append("invalid_gpt_header_crc")
        if reserved != 0 or my_lba != 1:
            anomalies.append("invalid_gpt_header_location")
        if not (
            1 < first_usable <= last_usable < total_lbas
            and 1 < alternate_lba < total_lbas
        ):
            anomalies.append("invalid_gpt_usable_range")
        entries_size = entry_count * entry_size
        entry_offset = entry_lba * 512
        entry_shape_valid = (
            0 < entry_count <= 4096
            and 128 <= entry_size <= 4096
            and entry_size & (entry_size - 1) == 0
            and entries_size <= 8 << 20
            and entry_lba >= 2
            and entry_offset + entries_size <= len(disk_data)
        )
        if not entry_shape_valid:
            anomalies.append("invalid_gpt_entry_array_range")
            entries_crc_valid = False
            entries = b""
        else:
            entries = disk_data[entry_offset : entry_offset + entries_size]
            entries_crc_valid = (
                binascii.crc32(entries) & 0xFFFFFFFF
            ) == stored_entries_crc
            if not entries_crc_valid:
                anomalies.append("invalid_gpt_entry_array_crc")
        summary = {
            "scheme": "GPT",
            "valid": not anomalies,
            "revision": f"0x{revision:08x}",
            "header_crc_valid": header_crc_valid,
            "entry_array_crc_valid": entries_crc_valid,
            "disk_guid": str(uuid.UUID(bytes_le=header[56:72])),
            "alternate_lba": alternate_lba,
            "first_usable_lba": first_usable,
            "last_usable_lba": last_usable,
            "entry_lba": entry_lba,
            "entry_count": entry_count,
            "entry_size": entry_size,
            "entries_scanned": min(entry_count, 128) if entry_shape_valid else 0,
            "entries_truncated": entry_count > 128,
            "anomalies": sorted(set(anomalies)),
        }
        if anomalies:
            return summary, [], []
        partitions = []
        extracted = []
        for index in range(min(entry_count, 128)):
            entry = entries[index * entry_size : (index + 1) * entry_size]
            type_guid = uuid.UUID(bytes_le=entry[:16])
            if type_guid.int == 0:
                continue
            unique_guid = uuid.UUID(bytes_le=entry[16:32])
            start_lba, end_lba, attributes = struct.unpack_from("<QQQ", entry, 32)
            offset = start_lba * 512
            size = (end_lba - start_lba + 1) * 512 if end_lba >= start_lba else 0
            range_valid = (
                first_usable <= start_lba <= end_lba <= last_usable
                and offset + size <= len(disk_data)
            )
            name = (
                entry[56:128].decode("utf-16-le", errors="replace").split("\x00", 1)[0]
            )
            partitions.append(
                {
                    "slot": index + 1,
                    "type_guid": str(type_guid),
                    "unique_guid": str(unique_guid),
                    "name": name,
                    "start_lba": start_lba,
                    "end_lba": end_lba,
                    "attributes": f"0x{attributes:016x}",
                    "offset": offset,
                    "size": size,
                    "range_valid": range_valid,
                }
            )
            if range_valid and size <= self.max_item:
                extracted.append(
                    (
                        f"disk_partition_{index + 1:03d}.bin",
                        disk_data[offset : offset + size],
                    )
                )
        return summary, partitions, extracted

    @staticmethod
    def _crc32c(data: bytes) -> int:
        value = 0xFFFFFFFF
        for byte in data:
            value ^= byte
            for _ in range(8):
                value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        return value ^ 0xFFFFFFFF

    def _parse_vhdx_header(self, data: bytes, offset: int) -> dict[str, Any] | None:
        if offset + 4096 > len(data) or data[offset : offset + 4] != b"head":
            return None
        raw = data[offset : offset + 4096]
        stored_checksum = struct.unpack_from("<I", raw, 4)[0]
        checksum_valid = (
            self._crc32c(raw[:4] + b"\x00" * 4 + raw[8:]) == stored_checksum
        )
        sequence = struct.unpack_from("<Q", raw, 8)[0]
        log_version, version, log_length, log_offset = struct.unpack_from(
            "<HHIQ", raw, 64
        )
        anomalies = []
        if not checksum_valid:
            anomalies.append("invalid_header_checksum")
        if version != 1:
            anomalies.append("invalid_header_version")
        if log_version != 0:
            anomalies.append("unsupported_log_version")
        if log_length and (log_length % (1 << 20) or log_offset % (1 << 20)):
            anomalies.append("invalid_log_alignment")
        if log_length and log_offset + log_length > len(data):
            anomalies.append("log_range_out_of_bounds")
        return {
            "offset": offset,
            "valid": checksum_valid and version == 1,
            "checksum_valid": checksum_valid,
            "sequence_number": sequence,
            "file_write_guid": str(uuid.UUID(bytes_le=raw[16:32])),
            "data_write_guid": str(uuid.UUID(bytes_le=raw[32:48])),
            "log_guid": str(uuid.UUID(bytes_le=raw[48:64])),
            "log_version": log_version,
            "version": version,
            "log_length": log_length,
            "log_offset": log_offset,
            "anomalies": anomalies,
        }

    def _parse_vhdx_regions(self, data: bytes, offset: int) -> dict[str, Any] | None:
        if offset + 65536 > len(data) or data[offset : offset + 4] != b"regi":
            return None
        raw = data[offset : offset + 65536]
        stored_checksum, count = struct.unpack_from("<II", raw, 4)
        checksum_valid = (
            self._crc32c(raw[:4] + b"\x00" * 4 + raw[8:]) == stored_checksum
        )
        if count > 2047:
            return {
                "offset": offset,
                "valid": False,
                "checksum_valid": checksum_valid,
                "entry_count": count,
                "regions": [],
                "anomalies": ["region_count_limit_exceeded"],
            }
        regions = []
        anomalies = []
        seen: set[str] = set()
        for index in range(count):
            at = 16 + index * 32
            guid = str(uuid.UUID(bytes_le=raw[at : at + 16]))
            file_offset, length, required = struct.unpack_from("<QII", raw, at + 16)
            name = self._VHDX_REGIONS.get(guid, "unknown")
            range_valid = (
                file_offset >= 1 << 20
                and file_offset % (1 << 20) == 0
                and length > 0
                and length % (1 << 20) == 0
                and file_offset + length <= len(data)
            )
            if guid in seen:
                anomalies.append("duplicate_region_guid")
            seen.add(guid)
            if not range_valid:
                anomalies.append("region_range_invalid")
            if required == 1 and name == "unknown":
                anomalies.append("unknown_required_region")
            regions.append(
                {
                    "guid": guid,
                    "name": name,
                    "file_offset": file_offset,
                    "length": length,
                    "required": bool(required),
                    "range_valid": range_valid,
                }
            )
        if not checksum_valid:
            anomalies.append("invalid_region_table_checksum")
        return {
            "offset": offset,
            "valid": checksum_valid and not anomalies,
            "checksum_valid": checksum_valid,
            "entry_count": count,
            "regions": regions,
            "anomalies": sorted(set(anomalies)),
        }

    def _parse_vhdx_metadata(
        self, data: bytes, region: dict[str, Any]
    ) -> dict[str, Any]:
        region_offset = int(region["file_offset"])
        region_length = int(region["length"])
        anomalies = []
        if (
            region_length < 65536
            or region_offset + region_length > len(data)
            or data[region_offset : region_offset + 8] != b"metadata"
        ):
            return {
                "valid": False,
                "items": [],
                "values": {},
                "anomalies": ["invalid_metadata_table_header"],
            }
        reserved, count = struct.unpack_from("<HH", data, region_offset + 8)
        if reserved != 0:
            anomalies.append("metadata_header_reserved_nonzero")
        if count > 2047 or 32 + count * 32 > 65536:
            return {
                "valid": False,
                "entry_count": count,
                "items": [],
                "values": {},
                "anomalies": [*anomalies, "metadata_entry_count_limit_exceeded"],
            }
        items = []
        values: dict[str, Any] = {}
        seen: set[tuple[str, bool]] = set()
        for index in range(count):
            at = region_offset + 32 + index * 32
            guid = str(uuid.UUID(bytes_le=data[at : at + 16]))
            item_offset, length, flags, reserved2 = struct.unpack_from(
                "<IIII", data, at + 16
            )
            name = self._VHDX_METADATA.get(guid, "unknown")
            is_user = bool(flags & 0x1)
            key = (guid, is_user)
            range_valid = (length == 0 and item_offset == 0) or (
                item_offset >= 65536
                and length <= 1 << 20
                and item_offset + length <= region_length
            )
            if key in seen:
                anomalies.append("duplicate_metadata_item")
            seen.add(key)
            if flags & ~0x7 or reserved2 != 0:
                anomalies.append("invalid_metadata_item_flags")
            if not range_valid:
                anomalies.append("metadata_item_range_invalid")
            if flags & 0x4 and name == "unknown":
                anomalies.append("unknown_required_metadata_item")
            item = {
                "guid": guid,
                "name": name,
                "offset": item_offset,
                "length": length,
                "is_user": is_user,
                "is_virtual_disk": bool(flags & 0x2),
                "is_required": bool(flags & 0x4),
                "range_valid": range_valid,
            }
            items.append(item)
            if not range_valid or name == "unknown":
                continue
            raw = data[
                region_offset + item_offset : region_offset + item_offset + length
            ]
            if name == "file_parameters" and length == 8:
                block_size, file_flags = struct.unpack_from("<II", raw)
                block_valid = (
                    1 << 20 <= block_size <= 256 << 20
                    and block_size & (block_size - 1) == 0
                    and file_flags & ~0x3 == 0
                )
                values[name] = {
                    "block_size": block_size,
                    "leave_blocks_allocated": bool(file_flags & 0x1),
                    "has_parent": bool(file_flags & 0x2),
                    "valid": block_valid,
                }
                if not block_valid:
                    anomalies.append("invalid_file_parameters")
            elif name == "virtual_disk_size" and length == 8:
                values[name] = struct.unpack_from("<Q", raw)[0]
            elif name == "virtual_disk_id" and length == 16:
                values[name] = str(uuid.UUID(bytes_le=raw))
            elif (
                name in ("logical_sector_size", "physical_sector_size") and length == 4
            ):
                sector_size = struct.unpack_from("<I", raw)[0]
                values[name] = sector_size
                if sector_size not in (512, 4096):
                    anomalies.append(f"invalid_{name}")
            elif name != "parent_locator":
                anomalies.append(f"invalid_{name}_length")

        required = {
            "file_parameters",
            "virtual_disk_size",
            "virtual_disk_id",
            "logical_sector_size",
            "physical_sector_size",
        }
        missing = sorted(required - values.keys())
        anomalies.extend(f"missing_metadata_item:{name}" for name in missing)
        file_parameters = values.get("file_parameters", {})
        if isinstance(file_parameters, dict) and file_parameters.get("has_parent"):
            if "parent_locator" not in {item["name"] for item in items}:
                anomalies.append("missing_parent_locator")
        virtual_size = values.get("virtual_disk_size")
        logical_sector = values.get("logical_sector_size")
        if (
            isinstance(virtual_size, int)
            and isinstance(logical_sector, int)
            and (virtual_size == 0 or virtual_size % logical_sector)
        ):
            anomalies.append("invalid_virtual_disk_size")
        return {
            "valid": not anomalies,
            "entry_count": count,
            "items": items,
            "values": values,
            "anomalies": sorted(set(anomalies)),
        }

    def _parse_vhdx_bat(
        self,
        data: bytes,
        region: dict[str, Any],
        metadata: dict[str, Any],
    ) -> tuple[dict[str, Any], bytes | None]:
        values = metadata.get("values", {})
        file_parameters = values.get("file_parameters", {})
        virtual_size = values.get("virtual_disk_size")
        logical_sector = values.get("logical_sector_size")
        block_size = file_parameters.get("block_size")
        has_parent = bool(file_parameters.get("has_parent"))
        anomalies = []
        if not all(
            isinstance(value, int) and value > 0
            for value in (virtual_size, logical_sector, block_size)
        ):
            return {
                "valid": False,
                "anomalies": ["missing_bat_geometry"],
            }, None
        payload_blocks = (virtual_size + block_size - 1) // block_size
        chunk_ratio = ((1 << 23) * logical_sector) // block_size
        if chunk_ratio <= 0:
            return {
                "valid": False,
                "anomalies": ["invalid_bat_chunk_ratio"],
            }, None
        last_bat_index = (
            payload_blocks - 1 + (payload_blocks - 1) // chunk_ratio
            if payload_blocks
            else 0
        )
        region_offset = int(region["file_offset"])
        region_length = int(region["length"])
        if (last_bat_index + 1) * 8 > region_length:
            anomalies.append("bat_region_too_small")
        scan_count = min(payload_blocks, 4096)
        entries = []
        state_counts: dict[str, int] = {}
        reconstructed = (
            bytearray(virtual_size)
            if not has_parent
            and payload_blocks <= 128
            and virtual_size <= self.max_item
            and not anomalies
            else None
        )
        reconstructable = reconstructed is not None
        state_names = {
            0: "not_present",
            1: "undefined",
            2: "zero",
            3: "unmapped",
            4: "reserved_4",
            5: "reserved_5",
            6: "fully_present",
            7: "partially_present",
        }
        for block_index in range(scan_count):
            bat_index = block_index + block_index // chunk_ratio
            at = region_offset + bat_index * 8
            if at + 8 > region_offset + region_length or at + 8 > len(data):
                anomalies.append("bat_entry_out_of_bounds")
                reconstructable = False
                break
            value = struct.unpack_from("<Q", data, at)[0]
            state = value & 0x7
            state_name = state_names[state]
            state_counts[state_name] = state_counts.get(state_name, 0) + 1
            file_offset = (value >> 20) * (1 << 20)
            reserved_valid = value & 0xFFFF8 == 0
            block_length = min(block_size, virtual_size - block_index * block_size)
            range_valid = True
            if state in (6, 7):
                range_valid = (
                    file_offset >= 1 << 20
                    and file_offset % (1 << 20) == 0
                    and file_offset + block_length <= len(data)
                )
            if not reserved_valid:
                anomalies.append("bat_reserved_bits_nonzero")
            if state in (4, 5) or (state == 7 and not has_parent):
                anomalies.append("invalid_payload_block_state")
            if not range_valid:
                anomalies.append("payload_block_range_invalid")
            if block_index < 128:
                entries.append(
                    {
                        "payload_block": block_index,
                        "bat_index": bat_index,
                        "state": state_name,
                        "file_offset": file_offset if state in (6, 7) else None,
                        "range_valid": range_valid,
                        "reserved_valid": reserved_valid,
                    }
                )
            if reconstructed is not None and reconstructable:
                start = block_index * block_size
                if state == 6 and range_valid and reserved_valid:
                    reconstructed[start : start + block_length] = data[
                        file_offset : file_offset + block_length
                    ]
                elif state == 2 and reserved_valid:
                    pass
                else:
                    reconstructable = False
        if scan_count < payload_blocks:
            reconstructable = False
        if anomalies:
            reconstructable = False
        output = (
            bytes(reconstructed)
            if reconstructed is not None and reconstructable
            else None
        )
        return {
            "valid": not anomalies,
            "has_parent": has_parent,
            "payload_block_count": payload_blocks,
            "chunk_ratio": chunk_ratio,
            "entries_scanned": scan_count,
            "entries_truncated": scan_count < payload_blocks,
            "state_counts": dict(sorted(state_counts.items())),
            "entries": entries,
            "reconstructable_within_limits": reconstructed is not None,
            "reconstructed": output is not None,
            "anomalies": sorted(set(anomalies)),
        }, output

    def _parse_vhdx(
        self, data: bytes
    ) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
        creator_raw = data[8:520]
        creator = creator_raw.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
        headers = [
            header
            for offset in (64 << 10, 128 << 10)
            if (header := self._parse_vhdx_header(data, offset)) is not None
        ]
        valid_headers = [header for header in headers if header["valid"]]
        current_header = (
            max(valid_headers, key=lambda item: int(item["sequence_number"]))
            if valid_headers
            else None
        )
        region_tables = [
            table
            for offset in (192 << 10, 256 << 10)
            if (table := self._parse_vhdx_regions(data, offset)) is not None
        ]
        anomalies = []
        if not valid_headers:
            anomalies.append("no_valid_header")
        if not any(table["valid"] for table in region_tables):
            anomalies.append("no_valid_region_table")
        active_regions: list[dict[str, Any]] = next(
            (table["regions"] for table in region_tables if table["valid"]), []
        )
        metadata_region = next(
            (
                region
                for region in active_regions
                if region["name"] == "metadata" and region["range_valid"]
            ),
            None,
        )
        metadata = (
            self._parse_vhdx_metadata(data, metadata_region)
            if metadata_region is not None
            else None
        )
        if metadata is None:
            anomalies.append("missing_metadata_region")
        elif not metadata["valid"]:
            anomalies.append("invalid_metadata_region")
        bat_region = next(
            (
                region
                for region in active_regions
                if region["name"] == "bat" and region["range_valid"]
            ),
            None,
        )
        bat = None
        disk_payload = None
        candidates: list[tuple[str, bytes]] = []
        partition_table = None
        partitions: list[dict[str, Any]] = []
        if bat_region is None:
            anomalies.append("missing_bat_region")
        elif metadata is not None and metadata["valid"]:
            bat, disk_payload = self._parse_vhdx_bat(data, bat_region, metadata)
            if not bat["valid"]:
                anomalies.append("invalid_bat_region")
            if disk_payload is not None:
                candidates.append(("virtual_disk_payload.bin", disk_payload))
                partition_table, partitions, partition_artifacts = (
                    self._partition_table(disk_payload)
                )
                candidates.extend(partition_artifacts)
        result = {
            "file_type": "VHDX",
            "creator": creator,
            "headers": headers,
            "current_header_offset": (
                current_header["offset"] if current_header is not None else None
            ),
            "region_tables": region_tables,
            "metadata": metadata,
            "bat": bat,
            "partition_table": partition_table,
            "partitions": partitions,
            "anomalies": anomalies,
            "execution_performed": False,
        }
        return result, candidates
