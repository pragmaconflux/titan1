from typing import Dict, Any, List, Optional
import logging
from pathlib import Path

from ..decoders.base import (
    Decoder, Base64Decoder, RecursiveBase64Decoder, GzipDecoder,
    Bz2Decoder, LzmaDecoder, ZlibDecoder, HexDecoder, XorDecoder, Rot13Decoder,
    PDFDecoder, OLEDecoder, UUDecoder, ASN1Decoder, QuotedPrintableDecoder, Base32Decoder
)
from .analyzers.base import Analyzer, ZipAnalyzer, TarAnalyzer, PEAnalyzer, ELFAnalyzer
from ..utils.helpers import sha256, entropy, looks_like_text, extract_iocs
from ..config import Config
from .scoring import ScoringEngine, PruningEngine
from ..plugins import PluginManager, PluginDecoder, PluginAnalyzer
from .graph_export import GraphExporter
from .smart_detection import SmartDetectionEngine

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
            # Enhanced pruning policies
            'enable_quality_pruning': self.config.get('enable_quality_pruning', True),
            'enable_resource_pruning': self.config.get('enable_resource_pruning', True),
            'enable_depth_based_limits': self.config.get('enable_depth_based_limits', True),
            'quality_decay_threshold': self.config.get('quality_decay_threshold', 0.05),
            'max_consecutive_low_scores': self.config.get('max_consecutive_low_scores', 3),
            'min_content_similarity': self.config.get('min_content_similarity', 0.8),
            'prune_empty_decodes': self.config.get('prune_empty_decodes', True),
            'prune_identical_content': self.config.get('prune_identical_content', True),
        })

        # Initialize smart detection engine
        self.smart_detector = SmartDetectionEngine()

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
        if self.config.get("decoders", {}).get("zlib", True):
            self.decoders.append(ZlibDecoder())
        if self.config.get("decoders", {}).get("hex", True):
            self.decoders.append(HexDecoder())
        if self.config.get("decoders", {}).get("rot13", True):
            self.decoders.append(Rot13Decoder())
        if self.config.get("decoders", {}).get("xor", True):
            self.decoders.append(XorDecoder())
        if self.config.get("decoders", {}).get("pdf", True):
            self.decoders.append(PDFDecoder())
        if self.config.get("decoders", {}).get("ole", True):
            self.decoders.append(OLEDecoder())
        
        # Initialize off-by-default decoders (will be enabled by smart detection)
        self.uuencoder = UUDecoder(enabled=self.config.get("decoders", {}).get("uuencode", False))
        self.asn1_decoder = ASN1Decoder(enabled=self.config.get("decoders", {}).get("asn1", False))
        self.qp_decoder = QuotedPrintableDecoder(enabled=self.config.get("decoders", {}).get("quoted_printable", False))
        self.base32_decoder = Base32Decoder(enabled=self.config.get("decoders", {}).get("base32", False))

        # Initialize analyzers
        self.analyzers: List[Analyzer] = []
        if self.config.get("analyzers", {}).get("zip", True):
            zip_config = {
                'max_zip_files': self.config.get('max_zip_files', 25),
                'max_zip_total_size': self.config.get('max_zip_total_size', 10 * 1024 * 1024),
                'max_zip_file_size': self.config.get('max_zip_file_size', 50 * 1024 * 1024),
                'max_compression_ratio': self.config.get('max_compression_ratio', 100),
                'enable_parallel_extraction': self.config.get('enable_parallel_extraction', True),
                'max_parallel_workers': self.config.get('max_parallel_workers', 4),
            }
            self.analyzers.append(ZipAnalyzer(zip_config))
        if self.config.get("analyzers", {}).get("tar", True):
            tar_config = {
                'max_tar_files': self.config.get('max_tar_files', 25),
                'max_tar_total_size': self.config.get('max_tar_total_size', 10 * 1024 * 1024),
                'max_tar_file_size': self.config.get('max_tar_file_size', 50 * 1024 * 1024),
                'max_compression_ratio': self.config.get('max_compression_ratio', 100),
                'enable_parallel_extraction': self.config.get('enable_parallel_extraction', True),
                'max_parallel_workers': self.config.get('max_parallel_workers', 4),
            }
            self.analyzers.append(TarAnalyzer(tar_config))
        if self.config.get("analyzers", {}).get("pe", True):
            self.analyzers.append(PEAnalyzer())
        if self.config.get("analyzers", {}).get("elf", True):
            self.analyzers.append(ELFAnalyzer())

        # Load plugins
        self.plugin_manager = PluginManager()
        plugin_dirs = self.config.get('plugin_dirs', [])
        for plugin_dir in plugin_dirs:
            self.plugin_manager.add_plugin_dir(Path(plugin_dir))

        # Add default plugin directory
        default_plugin_dir = Path.home() / ".titan_decoder" / "plugins"
        self.plugin_manager.add_plugin_dir(default_plugin_dir)

        # Add built-in plugin directory
        builtin_plugin_dir = Path(__file__).parent.parent / "plugins"
        self.plugin_manager.add_plugin_dir(builtin_plugin_dir)

        # Load plugins
        self.plugin_manager.load_plugins()

        # Add plugin decoders and analyzers
        self.decoders.extend(self.plugin_manager.get_decoders())
        self.analyzers.extend(self.plugin_manager.get_analyzers())

        self.nodes: List[AnalysisNode] = []

    def analyze_blob(self, data: bytes, parent_id: Optional[int] = None, depth: int = 0, is_decoded_content: bool = False) -> None:
        """Recursively analyze a blob of data with intelligent scoring and pruning."""
        # Safety checks
        if not data or len(data) == 0:
            logger.warning(f"Skipping empty data at depth {depth}")
            return
        
        # Hard depth limit as safety net
        if depth > self.MAX_RECURSION_DEPTH:
            logger.warning(f"Max recursion depth reached at depth {depth}")
            return

        # For root node and decoded content, always analyze. For speculative branches, check pruning.
        if not is_decoded_content and depth > 0 and self.pruning_engine.should_prune_node(
            node_score=0.0,  # Will be calculated after analysis
            depth=depth,
            current_node_count=len(self.nodes),
            data_size=len(data),
            content_type="Unknown",  # Will be determined during analysis
            is_decoded_content=is_decoded_content
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

        # Smart detection: Check if we should enable any off-by-default decoders
        detected_decoders = self.smart_detector.detect_format(data)
        if detected_decoders:
            logger.info(f"Smart detection found: {[d[0] for d in detected_decoders]}")
            for decoder_name, confidence in detected_decoders:
                if decoder_name == "uuencode":
                    self.uuencoder.enabled = True
                    if self.uuencoder not in self.decoders:
                        self.decoders.append(self.uuencoder)
                        logger.info(f"Enabled UUEncode decoder (confidence: {confidence:.2f})")
                elif decoder_name == "asn1":
                    self.asn1_decoder.enabled = True
                    if self.asn1_decoder not in self.decoders:
                        self.decoders.append(self.asn1_decoder)
                        logger.info(f"Enabled ASN.1 decoder (confidence: {confidence:.2f})")
                elif decoder_name == "quoted_printable":
                    self.qp_decoder.enabled = True
                    if self.qp_decoder not in self.decoders:
                        self.decoders.append(self.qp_decoder)
                        logger.info(f"Enabled QuotedPrintable decoder (confidence: {confidence:.2f})")
                elif decoder_name == "base32":
                    self.base32_decoder.enabled = True
                    if self.base32_decoder not in self.decoders:
                        self.decoders.append(self.base32_decoder)
                        logger.info(f"Enabled Base32 decoder (confidence: {confidence:.2f})")

        # Try decoders first with scoring
        best_score = 0.0
        best_decoder = None
        best_decoded = None

        for decoder in self.decoders:
            can_decode_result = decoder.can_decode(data)
            if can_decode_result:
                logger.debug(f"Trying decoder: {decoder.name}")
                decoded, success = decoder.decode(data)
                if success and decoded != data:
                    # Calculate score for this decoding
                    score = self.scoring_engine.calculate_decode_score(
                        data, decoded, decoder.name, depth
                    )
                    logger.debug(f"Decoder {decoder.name} score: {score:.3f}")

                    # Keep track of best scoring decode
                    if score > best_score:
                        best_score = score
                        best_decoder = decoder.name
                        best_decoded = decoded
            else:
                logger.debug(f"Decoder {decoder.name} cannot decode this data")

        # Apply best scoring decode if it meets threshold
        if best_decoded and best_score >= self.pruning_engine.min_score_threshold:
            logger.info(f"Applying decoder: {best_decoder} (score: {best_score:.3f})")
            node.decode_score = best_score
            node.decoder_used = best_decoder
            node.decoded_length = len(best_decoded)

            # Continue analysis with decoded data
            self.analyze_blob(best_decoded, node.id, depth + 1, is_decoded_content=True)
            return  # Stop after successful decoding

        # Try analyzers (for archives) if no decoder succeeded
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
                            content_type = "Text" if looks_like_text(content) else "Binary"
                            if not self.pruning_engine.should_prune_node(
                                node_score=archive_score,
                                depth=depth + 1,
                                current_node_count=len(self.nodes),
                                data_size=len(content),
                                content_type=content_type,
                                is_decoded_content=True
                            ):
                                self.analyze_blob(content, node.id, depth + 1, is_decoded_content=True)
                        return  # Stop after successful analysis
                except Exception as e:
                    logger.error(f"Analyzer {analyzer.name} failed: {e}")

        # No successful decoding or analysis
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

    def export_graph(self, format_type: str = "json", **kwargs) -> str:
        """Export the analysis graph in the specified format.

        Args:
            format_type: 'json', 'dot', or 'mermaid'
            **kwargs: Additional arguments for the exporter

        Returns:
            String representation of the graph in the requested format
        """
        exporter = GraphExporter([node.to_dict() for node in self.nodes])

        if format_type == "json":
            return exporter.to_json(**kwargs)
        elif format_type == "dot":
            return exporter.to_dot(**kwargs)
        elif format_type == "mermaid":
            return exporter.to_mermaid(**kwargs)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def save_graph(self, filepath: Path, format_type: str = "json", **kwargs):
        """Save the analysis graph to a file.

        Args:
            filepath: Path to save the graph
            format_type: 'json', 'dot', or 'mermaid'
            **kwargs: Additional arguments for the exporter
        """
        exporter = GraphExporter([node.to_dict() for node in self.nodes])

        if format_type == "json":
            exporter.save_json(filepath, **kwargs)
        elif format_type == "dot":
            exporter.save_dot(filepath, **kwargs)
        elif format_type == "mermaid":
            exporter.save_mermaid(filepath, **kwargs)
        else:
            raise ValueError(f"Unsupported format: {format_type}")