from typing import Dict, Any, List, Optional
import logging

from ..decoders.base import (
    Decoder, Base64Decoder, RecursiveBase64Decoder, GzipDecoder,
    Bz2Decoder, LzmaDecoder, HexDecoder, XorDecoder, Rot13Decoder
)
from .analyzers.base import Analyzer, ZipAnalyzer, TarAnalyzer
from ..utils.helpers import sha256, entropy, looks_like_text, extract_iocs
from ..config import Config

logger = logging.getLogger(__name__)


class AnalysisNode:
    """Represents a node in the analysis tree."""

    def __init__(self, data: bytes, parent_id: Optional[int], depth: int, method: str):
        self.id = None  # Set by engine
        self.parent = parent_id
        self.depth = depth
        self.method = method
        self.source_length = len(data)
        self.decoded_length = len(data)
        self.sha256 = sha256(data)
        self.entropy = entropy(data)
        self.content_type = "Text" if looks_like_text(data) else "Binary"
        self.content_preview = data[:500].decode("utf-8", errors="ignore")
        self.children = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "parent": self.parent,
            "depth": self.depth,
            "method": self.method,
            "source_length": self.source_length,
            "decoded_length": self.decoded_length,
            "sha256": self.sha256,
            "entropy": self.entropy,
            "content_type": self.content_type,
            "content_preview": self.content_preview,
        }


class TitanEngine:
    """Main decoding and analysis engine."""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.MAX_RECURSION_DEPTH = self.config.get("max_recursion_depth", 5)

        # Initialize decoders based on config
        self.decoders: List[Decoder] = []
        if self.config.get("decoders", {}).get("recursive_base64", True):
            self.decoders.append(RecursiveBase64Decoder())
        if self.config.get("decoders", {}).get("base64", True):
            self.decoders.append(Base64Decoder())
        if self.config.get("decoders", {}).get("gzip", True):
            self.decoders.append(GzipDecoder())
        if self.config.get("decoders", {}).get("bz2", True):
            self.decoders.append(Bz2Decoder())
        if self.config.get("decoders", {}).get("lzma", True):
            self.decoders.append(LzmaDecoder())
        if self.config.get("decoders", {}).get("hex", True):
            self.decoders.append(HexDecoder())
        if self.config.get("decoders", {}).get("rot13", True):
            self.decoders.append(Rot13Decoder())
        if self.config.get("decoders", {}).get("xor", True):
            self.decoders.append(XorDecoder())

        # Initialize analyzers
        self.analyzers: List[Analyzer] = []
        if self.config.get("analyzers", {}).get("zip", True):
            self.analyzers.append(ZipAnalyzer())
        if self.config.get("analyzers", {}).get("tar", True):
            self.analyzers.append(TarAnalyzer())

        self.nodes: List[AnalysisNode] = []

    def analyze_blob(self, data: bytes, parent_id: Optional[int] = None, depth: int = 0) -> None:
        """Recursively analyze a blob of data."""
        if depth > self.MAX_RECURSION_DEPTH:
            logger.warning(f"Max recursion depth reached at depth {depth}")
            return

        node = AnalysisNode(data, parent_id, depth, "ANALYZE")
        node.id = len(self.nodes)
        self.nodes.append(node)

        # Try analyzers first (for archives)
        for analyzer in self.analyzers:
            if analyzer.can_analyze(data):
                logger.info(f"Using analyzer: {analyzer.name}")
                try:
                    extracted = analyzer.analyze(data)
                    for name, content in extracted:
                        self.analyze_blob(content, node.id, depth + 1)
                    return  # Stop after successful analysis
                except Exception as e:
                    logger.error(f"Analyzer {analyzer.name} failed: {e}")

        # Try decoders
        for decoder in self.decoders:
            if decoder.can_decode(data):
                logger.info(f"Trying decoder: {decoder.name}")
                decoded, success = decoder.decode(data)
                if success and decoded != data:
                    node.decoded_length = len(decoded)
                    self.analyze_blob(decoded, node.id, depth + 1)
                    return  # Stop after successful decode

        # If no decoder worked, this is a leaf node
        logger.info(f"Leaf node reached at depth {depth}")

    def run_analysis(self, input_data: bytes) -> Dict[str, Any]:
        """Run full analysis on input data."""
        self.nodes = []
        self.analyze_blob(input_data, None, 0)

        # Extract IOCs from all text nodes
        all_text = "\n".join(
            node.content_preview for node in self.nodes
            if node.content_type == "Text"
        )

        return {
            "meta": {
                "tool": "Titan Decoder Engine",
                "version": "2.0.0",
            },
            "node_count": len(self.nodes),
            "nodes": [node.to_dict() for node in self.nodes],
            "iocs": extract_iocs(all_text),
        }