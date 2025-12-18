from abc import ABC, abstractmethod
from typing import Dict, Any, List, Tuple
import zipfile
import tarfile
import io
import struct
import concurrent.futures
import threading

from ...utils.helpers import looks_like_zip


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


class ZipAnalyzer(Analyzer):
    """ZIP file analyzer with comprehensive safety checks and parallel extraction."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.max_files = self.config.get('max_zip_files', 25)
        self.max_total_size = self.config.get('max_zip_total_size', 10 * 1024 * 1024)  # 10MB
        self.max_file_size = self.config.get('max_zip_file_size', 50 * 1024 * 1024)    # 50MB per file
        self.max_compression_ratio = self.config.get('max_compression_ratio', 100)     # 100:1 max
        self.enable_parallel = self.config.get('enable_parallel_extraction', True)
        self.max_workers = self.config.get('max_parallel_workers', 4)

    def can_analyze(self, data: bytes) -> bool:
        return looks_like_zip(data)

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Analyze ZIP file with safety checks and optional parallel extraction."""
        extracted = []
        total_size = 0
        zip_size = len(data)

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                # Pre-scan for safety issues
                safe_files = self._pre_scan_zip(z, zip_size)
                if not safe_files:
                    return []  # No safe files found

                # Extract safe files
                if self.enable_parallel and len(safe_files) > 1:
                    # Use parallel extraction for multiple files
                    extracted = self._extract_parallel(z, safe_files)
                else:
                    # Use sequential extraction for single files or when parallel is disabled
                    extracted = self._extract_sequential(z, safe_files)

                # Apply final size limits and path sanitization
                final_extracted = []
                for filename, content in extracted:
                    if len(final_extracted) >= self.max_files:
                        break

                    content_size = len(content)
                    if content_size > self.max_file_size:
                        continue
                    if total_size + content_size > self.max_total_size:
                        break

                    # Path traversal protection (already done in parallel version)
                    safe_filename = self._sanitize_filename(filename)
                    final_extracted.append((safe_filename, content))
                    total_size += content_size

        except Exception:
            # Invalid ZIP or other error
            pass

        return final_extracted

    def _extract_sequential(self, zip_file: zipfile.ZipFile, safe_files: List[str]) -> List[Tuple[str, bytes]]:
        """Extract files sequentially."""
        extracted = []
        for filename in safe_files:
            try:
                content = zip_file.read(filename)
                extracted.append((filename, content))
            except Exception:
                # Skip files that can't be read
                continue
        return extracted

    def _extract_parallel(self, zip_file: zipfile.ZipFile, safe_files: List[str]) -> List[Tuple[str, bytes]]:
        """Extract files in parallel using thread pool."""
        extracted = []

        # Create a thread-safe container for results
        results = []
        lock = threading.Lock()

        def extract_single_file(filename: str):
            try:
                content = zip_file.read(filename)
                with lock:
                    results.append((filename, content))
            except Exception:
                # Skip files that can't be read
                pass

        # Use ThreadPoolExecutor for I/O bound operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, len(safe_files))) as executor:
            # Submit all extraction tasks
            futures = [executor.submit(extract_single_file, filename) for filename in safe_files]

            # Wait for all tasks to complete
            concurrent.futures.wait(futures)

        return results

    def _pre_scan_zip(self, zip_file: zipfile.ZipFile, zip_size: int) -> List[str]:
        """Pre-scan ZIP contents for safety issues. Returns list of safe filenames."""
        safe_files = []

        for info in zip_file.infolist():
            # Skip directories
            if info.is_dir():
                continue

            # Check for path traversal attacks
            if '..' in info.filename or info.filename.startswith('/'):
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
            # (rough estimate based on current safe files)
            current_safe_size = sum(zip_file.getinfo(f).file_size for f in safe_files)
            if current_safe_size + info.file_size > self.max_total_size:
                continue

            safe_files.append(info.filename)

        return safe_files

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal and other issues."""
        import os

        # Remove path separators and normalize
        safe_name = os.path.basename(filename)

        # Remove any remaining dangerous characters
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in '._- ')

        # Ensure it's not empty
        if not safe_name:
            safe_name = "extracted_file"

        return safe_name

    @property
    def name(self) -> str:
        return "ZIP"


class TarAnalyzer(Analyzer):
    """TAR file analyzer with comprehensive safety checks and parallel extraction."""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.max_files = self.config.get('max_tar_files', 25)
        self.max_total_size = self.config.get('max_tar_total_size', 10 * 1024 * 1024)  # 10MB
        self.max_file_size = self.config.get('max_tar_file_size', 50 * 1024 * 1024)    # 50MB per file
        self.max_compression_ratio = self.config.get('max_compression_ratio', 100)     # 100:1 max
        self.enable_parallel = self.config.get('enable_parallel_extraction', True)
        self.max_workers = self.config.get('max_parallel_workers', 4)

    def can_analyze(self, data: bytes) -> bool:
        return data.startswith(b"\x75\x73\x74\x61\x72") or len(data) >= 512 and data[257:263] == b"ustar\x00"

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Analyze TAR file with safety checks and optional parallel extraction."""
        extracted = []
        total_size = 0
        tar_size = len(data)

        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                # Pre-scan for safety issues
                safe_members = self._pre_scan_tar(t, tar_size)
                if not safe_members:
                    return []  # No safe files found

                # Extract safe files
                if self.enable_parallel and len(safe_members) > 1:
                    # Use parallel extraction for multiple files
                    extracted = self._extract_parallel(t, safe_members)
                else:
                    # Use sequential extraction for single files or when parallel is disabled
                    extracted = self._extract_sequential(t, safe_members)

                # Apply final size limits and path sanitization
                final_extracted = []
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

        return extracted

    def _extract_sequential(self, tar_file: tarfile.TarFile, safe_members: List[tarfile.TarInfo]) -> List[Tuple[tarfile.TarInfo, bytes]]:
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

    def _extract_parallel(self, tar_file: tarfile.TarFile, safe_members: List[tarfile.TarInfo]) -> List[Tuple[tarfile.TarInfo, bytes]]:
        """Extract files in parallel using thread pool."""
        extracted = []

        # Create a thread-safe container for results
        results = []
        lock = threading.Lock()

        def extract_single_file(member: tarfile.TarInfo):
            try:
                content = tar_file.extractfile(member).read()
                with lock:
                    results.append((member, content))
            except Exception:
                # Skip files that can't be read
                pass

        # Use ThreadPoolExecutor for I/O bound operations
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_workers, len(safe_members))) as executor:
            # Submit all extraction tasks
            futures = [executor.submit(extract_single_file, member) for member in safe_members]

            # Wait for all tasks to complete
            concurrent.futures.wait(futures)

        return results

    def _pre_scan_tar(self, tar_file: tarfile.TarFile, tar_size: int) -> List[tarfile.TarInfo]:
        """Pre-scan TAR contents for safety issues. Returns list of safe TarInfo objects."""
        safe_members = []

        for member in tar_file.getmembers():
            # Skip non-files
            if not member.isfile():
                continue

            # Check for path traversal attacks
            if '..' in member.name or member.name.startswith('/'):
                continue

            # Check compression ratio (tar bomb detection)
            # For TAR files, we check the ratio of uncompressed to stored size
            if member.size > 0 and hasattr(member, 'size'):
                # TAR files don't have compressed size in the same way, but we can estimate
                # based on the member size vs. a reasonable compression expectation
                # This is a heuristic since TAR itself doesn't compress
                if member.size > self.max_file_size:
                    continue

            # Check for files that would make total size too large
            current_safe_size = sum(m.size for m in safe_members)
            if current_safe_size + member.size > self.max_total_size:
                continue

            safe_members.append(member)

        return safe_members

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename to prevent path traversal and other issues."""
        import os

        # Remove path separators and normalize
        safe_name = os.path.basename(filename)

        # Remove any remaining dangerous characters
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in '._- ')

        # Ensure it's not empty
        if not safe_name:
            safe_name = "extracted_file"

        return safe_name

    @property
    def name(self) -> str:
        return "TAR"


class PEAnalyzer(Analyzer):
    """PE (Portable Executable) file metadata analyzer."""

    def can_analyze(self, data: bytes) -> bool:
        """Check if data looks like a PE file."""
        if len(data) < 64:
            return False
        # Check for MZ header
        if data[:2] != b'MZ':
            return False
        # Check for PE signature at offset from e_lfanew
        try:
            e_lfanew = struct.unpack('<I', data[60:64])[0]
            if e_lfanew + 24 > len(data):
                return False
            return data[e_lfanew:e_lfanew+4] == b'PE\x00\x00'
        except:
            return False

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Extract PE metadata without executing the file."""
        metadata = self._extract_pe_metadata(data)
        if metadata:
            # Return metadata as JSON string
            import json
            metadata_json = json.dumps(metadata, indent=2).encode('utf-8')
            return [("pe_metadata.json", metadata_json)]
        return []

    def _extract_pe_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract key metadata from PE file."""
        try:
            # DOS header
            e_lfanew = struct.unpack('<I', data[60:64])[0]

            # PE signature offset
            pe_offset = e_lfanew

            # COFF header (after PE signature)
            coff_offset = pe_offset + 4

            if coff_offset + 20 > len(data):
                return None

            # Parse COFF header
            machine, num_sections, time_date_stamp, ptr_to_sym_table, num_symbols, \
            size_of_opt_header, characteristics = struct.unpack('<HHIIIHH', data[coff_offset:coff_offset+20])

            # Machine types
            machine_types = {
                0x014c: "x86",
                0x0200: "IA64",
                0x8664: "x64",
                0x01c0: "ARM",
                0x01c4: "ARM64",
                0xaa64: "ARM64",
            }

            # Optional header
            metadata = {
                "file_type": "PE",
                "machine_type": machine_types.get(machine, f"Unknown (0x{machine:04x})"),
                "num_sections": num_sections,
                "time_date_stamp": time_date_stamp,
                "characteristics": f"0x{characteristics:04x}",
                "has_optional_header": size_of_opt_header > 0,
            }

            if size_of_opt_header > 0:
                opt_offset = coff_offset + 20
                if opt_offset + 24 <= len(data):
                    # Parse optional header (first 24 bytes are common)
                    magic, major_linker, minor_linker, size_of_code, size_of_init_data, \
                    size_of_uninit_data, entry_point, base_of_code = struct.unpack('<HBBIIIIII', data[opt_offset:opt_offset+24])

                    metadata.update({
                        "magic": "PE32+" if magic == 0x20b else "PE32" if magic == 0x10b else f"Unknown (0x{magic:04x})",
                        "entry_point": f"0x{entry_point:08x}",
                        "size_of_code": size_of_code,
                        "size_of_init_data": size_of_init_data,
                        "size_of_uninit_data": size_of_uninit_data,
                    })

                    # For PE32, image base is at offset 28
                    if magic == 0x10b and opt_offset + 28 <= len(data):
                        image_base = struct.unpack('<I', data[opt_offset+28:opt_offset+32])[0]
                        metadata["image_base"] = f"0x{image_base:08x}"

                    # For PE32+, image base is at offset 24
                    elif magic == 0x20b and opt_offset + 24 <= len(data):
                        image_base = struct.unpack('<Q', data[opt_offset+24:opt_offset+32])[0]
                        metadata["image_base"] = f"0x{image_base:016x}"

            return metadata

        except Exception as e:
            return {"error": f"Failed to parse PE metadata: {str(e)}"}

    @property
    def name(self) -> str:
        return "PE"


class ELFAnalyzer(Analyzer):
    """ELF (Executable and Linkable Format) file metadata analyzer."""

    def can_analyze(self, data: bytes) -> bool:
        """Check if data looks like an ELF file."""
        if len(data) < 16:
            return False
        # Check for ELF magic number
        return data[:4] == b'\x7fELF'

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Extract ELF metadata without executing the file."""
        metadata = self._extract_elf_metadata(data)
        if metadata:
            # Return metadata as JSON string
            import json
            metadata_json = json.dumps(metadata, indent=2).encode('utf-8')
            return [("elf_metadata.json", metadata_json)]
        return []

    def _extract_elf_metadata(self, data: bytes) -> Dict[str, Any]:
        """Extract key metadata from ELF file."""
        try:
            if len(data) < 64:
                return None

            # Parse ELF header (64 bytes)
            # e_ident (16 bytes)
            ei_class, ei_data, ei_version, ei_osabi = data[4], data[5], data[6], data[7]

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

            # Rest of header
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, \
            e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack('<HHIIIIIHHHHHH', data[16:52])

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
                "machine_type": machine_types.get(e_machine, f"Unknown (0x{e_machine:04x})"),
                "entry_point": f"0x{e_entry:016x}" if ei_class == 2 else f"0x{e_entry:08x}",
                "program_headers_offset": e_phoff,
                "section_headers_offset": e_shoff,
                "num_program_headers": e_phnum,
                "num_section_headers": e_shnum,
                "flags": f"0x{e_flags:08x}",
            }

            return metadata

        except Exception as e:
            return {"error": f"Failed to parse ELF metadata: {str(e)}"}

    @property
    def name(self) -> str:
        return "ELF"