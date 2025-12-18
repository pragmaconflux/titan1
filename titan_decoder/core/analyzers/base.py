from abc import ABC, abstractmethod
from typing import Dict, Any, List, Tuple
import zipfile
import io

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
    """ZIP file analyzer."""

    MAX_FILES = 25
    MAX_TOTAL_SIZE = 10 * 1024 * 1024  # 10MB

    def can_analyze(self, data: bytes) -> bool:
        return looks_like_zip(data)

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        extracted = []
        total_size = 0

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for info in z.infolist():
                    if len(extracted) >= self.MAX_FILES:
                        break
                    if info.file_size + total_size > self.MAX_TOTAL_SIZE:
                        break
                    if info.is_dir():
                        continue

                    content = z.read(info.filename)
                    extracted.append((info.filename, content))
                    total_size += len(content)
        except Exception:
            pass

        return extracted

    @property
    def name(self) -> str:
        return "ZIP"


class TarAnalyzer(Analyzer):
    """TAR file analyzer."""

    def can_analyze(self, data: bytes) -> bool:
        return data.startswith(b"\x75\x73\x74\x61\x72") or len(data) >= 512 and data[257:263] == b"ustar\x00"

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        import tarfile

        extracted = []
        try:
            with tarfile.open(fileobj=io.BytesIO(data)) as t:
                for member in t.getmembers():
                    if member.isfile():
                        content = t.extractfile(member).read()
                        extracted.append((member.name, content))
        except Exception:
            pass

        return extracted

    @property
    def name(self) -> str:
        return "TAR"