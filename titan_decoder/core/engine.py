from typing import Dict, Any, List, Optional
import logging

from ..decoders.base import (
    Decoder, Base64Decoder, RecursiveBase64Decoder, GzipDecoder,
    Bz2Decoder, LzmaDecoder, HexDecoder, XorDecoder, Rot13Decoder
)
from .analyzers.base import Analyzer, ZipAnalyzer, TarAnalyzer
from ..utils.helpers import sha256, entropy, looks_like_text, extract_iocs
from ..config import Config
from .scoring import ScoringEngine, PruningEngine

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

        # Scoring information
        self.decode_score = 0.0
        self.decoder_used = None
        self.pruned = False

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
            "decode_score": self.decode_score,
            "decoder_used": self.decoder_used,
            "pruned": self.pruned,
        }


class TitanEngine:
    """Main decoding and analysis engine."""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.MAX_RECURSION_DEPTH = self.config.get("max_recursion_depth", 5)

        # Initialize scoring and pruning engines
        self.scoring_engine = ScoringEngine()
        self.pruning_engine = PruningEngine({
            'max_node_count': self.config.get('max_node_count', 100),
            'min_score_threshold': self.config.get('min_score_threshold', 0.01),
            'max_recursion_depth': self.MAX_RECURSION_DEPTH,
            'max_data_size': self.config.get('max_data_size', 50 * 1024 * 1024),
        })

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

    def analyze_blob(self, data: bytes, parent_id: Optional[int] = None, depth: int = 0, is_decoded_content: bool = False) -> None:
        """Recursively analyze a blob of data with intelligent scoring and pruning."""
        # Hard depth limit as safety net
        if depth > self.MAX_RECURSION_DEPTH:
            logger.warning(f"Max recursion depth reached at depth {depth}")
            return

        # For root node and decoded content, always analyze. For speculative branches, check pruning.
        if not is_decoded_content and depth > 0 and self.pruning_engine.should_prune_node(
            node_score=0.0,  # Will be calculated after analysis
            depth=depth,
            current_node_count=len(self.nodes),
            data_size=len(data)
        ):
            logger.info(f"Pruning node at depth {depth} (pre-analysis check)")
            return

        node = AnalysisNode(data, parent_id, depth, "ANALYZE")
        node.id = len(self.nodes)
        self.nodes.append(node)

        # Check for duplicate content (hash deduplication)
        existing_hashes = {n.sha256 for n in self.nodes[:-1]}  # Exclude current node
        if node.sha256 in existing_hashes:
            logger.info(f"Duplicate content detected, skipping analysis")
            node.pruned = True
            return

        # Try analyzers first (for archives)
        for analyzer in self.analyzers:
            if analyzer.can_analyze(data):
                logger.info(f"Using analyzer: {analyzer.name}")
                try:
                    extracted = analyzer.analyze(data)
                    if extracted:  # Only proceed if extraction succeeded
                        node.method = f"ANALYZE_{analyzer.name}"
                        # Calculate score for archive extraction
                        total_extracted_size = sum(len(content) for _, content in extracted)
                        archive_score = self.scoring_engine.calculate_decode_score(
                            data, b''.join(content for _, content in extracted),
                            analyzer.name, depth
                        )
                        node.decode_score = archive_score
                        node.decoder_used = analyzer.name

                        # Analyze each extracted file
                        for name, content in extracted:
                            if not self.pruning_engine.should_prune_node(
                                node_score=archive_score,
                                depth=depth + 1,
                                current_node_count=len(self.nodes),
                                data_size=len(content)
                            ):
                                self.analyze_blob(content, node.id, depth + 1, is_decoded_content=True)
                        return  # Stop after successful analysis
                except Exception as e:
                    logger.error(f"Analyzer {analyzer.name} failed: {e}")

        # Try decoders with scoring
        best_score = 0.0
        best_decoder = None
        best_decoded = None

        for decoder in self.decoders:
            if decoder.can_decode(data):
                logger.debug(f"Trying decoder: {decoder.name}")
                decoded, success = decoder.decode(data)
                if success and decoded != data:
                    # Calculate score for this decoding
                    score = self.scoring_engine.calculate_decode_score(
                        data, decoded, decoder.name, depth
                    )

                    # Keep track of best scoring decode
                    if score > best_score:
                        best_score = score
                        best_decoder = decoder.name
                        best_decoded = decoded

        # Apply best scoring decode if it meets threshold
        if best_decoded and best_score >= self.pruning_engine.min_score_threshold:
            logger.info(f"Applying decoder: {best_decoder} (score: {best_score:.3f})")
            node.decode_score = best_score
            node.decoder_used = best_decoder
            node.decoded_length = len(best_decoded)

            # Continue analysis with decoded data
            self.analyze_blob(best_decoded, node.id, depth + 1, is_decoded_content=True)
        else:
            # No successful decoding or score too low
            logger.info(f"Leaf node reached at depth {depth} (score: {best_score:.3f})")
            if best_score < self.pruning_engine.min_score_threshold:
                node.pruned = True

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