from typing import Any, Callable, Dict, List, Optional
import logging
from pathlib import Path
import time
import uuid
from datetime import datetime, timezone
import sys
import platform
import copy

from ..decoders.base import (
    Decoder,
    Base64Decoder,
    RecursiveBase64Decoder,
    Base64UrlDecoder,
    PemArmorDecoder,
    GzipDecoder,
    Bz2Decoder,
    LzmaDecoder,
    ZlibDecoder,
    HexDecoder,
    XorDecoder,
    Rot13Decoder,
    PDFDecoder,
    OLEDecoder,
    UUDecoder,
    ASN1Decoder,
    QuotedPrintableDecoder,
    Base32Decoder,
    URLDecoder,
    HTMLEntityDecoder,
    UnicodeEscapeDecoder,
    Utf16Decoder,
)
from ..decoders.advanced import (
    Ascii85Decoder,
    Base58Decoder,
    Base91Decoder,
    BrotliDecoder,
    JavaScriptEscapeDecoder,
    JavaScriptEmulationDecoder,
    PowerShellEncodedCommandDecoder,
    RawDeflateDecoder,
    ZstandardDecoder,
)
from .analyzers.base import Analyzer, ZipAnalyzer, TarAnalyzer, PEAnalyzer, ELFAnalyzer
from .analyzers.executable_formats import (
    DexAnalyzer,
    MachOAnalyzer,
    VirtualDiskAnalyzer,
)
from .analyzers.carving import EmbeddedPayloadAnalyzer
from .analyzers.steganography import SteganographyAnalyzer
from .analyzers.emulation import X86ShellcodeEmulationAnalyzer
from .analyzers.structured import (
    EmailAnalyzer,
    LnkAnalyzer,
    MsiAnalyzer,
    OneNoteAnalyzer,
    OfficeAnalyzer,
    OptionalArchiveAnalyzer,
    RtfAnalyzer,
    ScriptAnalyzer,
)
from ..utils.helpers import sha256, entropy, looks_like_text, extract_iocs
from ..config import Config
from .scoring import ScoringEngine, PruningEngine
from ..plugins import PluginManager
from .graph_export import GraphExporter
from .smart_detection import SmartDetectionEngine
from .. import __version__ as TITAN_VERSION

logger = logging.getLogger(__name__)


SCHEMA_VERSION = "1.2"


class AnalysisNode:
    """Represents a node in the analysis tree."""

    def __init__(self, data: bytes, parent_id: Optional[int], depth: int, method: str):
        # Retain an in-memory reference for bounded post-analysis scanners. Raw
        # bytes are deliberately excluded from the JSON report.
        self._data = data
        self.id = None  # Set by engine
        self.parent = parent_id
        self.depth = depth
        self.method = method
        self.source_length = len(data)
        self.decoded_length = len(data)
        self.sha256 = sha256(data)
        self.entropy = entropy(data)
        self.content_type = "Text" if looks_like_text(data) else "Binary"
        # Preview is used for downstream IOC and lightweight forensics extraction.
        # Keep it small enough to avoid memory bloat but large enough to capture
        # meaningful context beyond headers.
        self.content_preview = data[:2000].decode("utf-8", errors="ignore")

        # Scoring information
        self.decode_score = 0.0
        self.decoder_used = None
        self.pruned = False
        self.analysis_state = "pending"
        self.termination_reason: Optional[str] = None

        # Provenance: how this blob was produced. ``artifact_name`` is the label
        # the producing analyzer gave the extracted item (e.g. a CFB stream path
        # or an archive member name); ``provenance`` is the full derivation
        # record filled in by the engine once the tree is complete.
        self.artifact_name: Optional[str] = None
        self.provenance: Optional[Dict[str, Any]] = None
        # Set when a composing pass (embedded-payload carving) produced this
        # node, so provenance names the pass that actually recovered it rather
        # than whichever analyzer later claimed the parent, and records the
        # byte offset the region was carved from.
        self.produced_by: Optional[str] = None
        self.source_offset: Optional[int] = None

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
            "analysis_state": self.analysis_state,
            "termination_reason": self.termination_reason,
            "artifact_name": self.artifact_name,
            "provenance": self.provenance,
        }


class TitanEngine:
    """Main decoding and analysis engine."""

    def __init__(
        self,
        config: Config = None,
        *,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: Any = None,
    ):
        self.config = config or Config()
        self.progress_callback = progress_callback
        self.cancel_event = cancel_event
        self.MAX_RECURSION_DEPTH = self.config.get("max_recursion_depth", 5)

        # Run-level bounds / telemetry
        self.analysis_timeout_seconds = int(
            self.config.get("analysis_timeout_seconds", 300)
        )
        self.decode_timeout_seconds = int(self.config.get("decode_timeout_seconds", 10))
        self.analyzer_timeout_seconds = int(
            self.config.get("analyzer_timeout_seconds", self.decode_timeout_seconds)
        )
        self.max_memory_mb = int(self.config.get("max_memory_mb", 1024))
        self.max_ioc_scan_bytes = max(
            0, int(self.config.get("max_ioc_scan_bytes", 1024 * 1024))
        )

        self.include_decision_trace = bool(
            self.config.get("include_decision_trace", False)
        )
        self.decision_trace: List[Dict[str, Any]] = []
        self._analysis_started_monotonic: float | None = None
        self._analysis_deadline_monotonic: float | None = None

        from .resource_manager import ResourceManager

        self.resource_manager = ResourceManager(self.config._config)

        # Initialize scoring and pruning engines
        self.scoring_engine = ScoringEngine()
        self.pruning_engine = PruningEngine(
            {
                "max_node_count": self.config.get("max_node_count", 100),
                "min_score_threshold": self.config.get("min_score_threshold", 0.01),
                "max_recursion_depth": self.MAX_RECURSION_DEPTH,
                "max_data_size": self.config.get("max_data_size", 50 * 1024 * 1024),
                # Pruning policies
                "enable_quality_pruning": self.config.get(
                    "enable_quality_pruning", True
                ),
                "enable_resource_pruning": self.config.get(
                    "enable_resource_pruning", True
                ),
                "enable_depth_based_limits": self.config.get(
                    "enable_depth_based_limits", True
                ),
            }
        )

        # Initialize smart detection engine
        self.smart_detector = SmartDetectionEngine()

        # Initialize decoders based on config
        # Cap decompressed output to defend against decompression bombs.
        max_decompressed = int(self.config.get("max_data_size", 50 * 1024 * 1024))
        self.decoders: List[Decoder] = []
        if self.config.get("decoders", {}).get("recursive_base64", True):
            self.decoders.append(RecursiveBase64Decoder())
        if self.config.get("decoders", {}).get("base64", True):
            self.decoders.append(Base64Decoder())
        if self.config.get("decoders", {}).get("base64url", True):
            self.decoders.append(Base64UrlDecoder())
        if self.config.get("decoders", {}).get("pem", True):
            self.decoders.append(PemArmorDecoder())
        if self.config.get("decoders", {}).get("gzip", True):
            self.decoders.append(GzipDecoder(max_decompressed))
        if self.config.get("decoders", {}).get("bz2", True):
            self.decoders.append(Bz2Decoder(max_decompressed))
        if self.config.get("decoders", {}).get("lzma", True):
            self.decoders.append(LzmaDecoder(max_decompressed))
        if self.config.get("decoders", {}).get("zlib", True):
            self.decoders.append(ZlibDecoder(max_decompressed))
        if self.config.get("decoders", {}).get("hex", True):
            self.decoders.append(HexDecoder())
        if self.config.get("decoders", {}).get("rot13", True):
            self.decoders.append(Rot13Decoder())
        if self.config.get("decoders", {}).get("xor", True):
            self.decoders.append(XorDecoder())
        if self.config.get("decoders", {}).get("pdf", True):
            self.decoders.append(PDFDecoder(max_decompressed))
        if self.config.get("decoders", {}).get("ole", True):
            self.decoders.append(OLEDecoder(max_decompressed))
        if self.config.get("decoders", {}).get("url", True):
            self.decoders.append(URLDecoder())
        if self.config.get("decoders", {}).get("html_entity", True):
            self.decoders.append(HTMLEntityDecoder())
        if self.config.get("decoders", {}).get("unicode_escape", True):
            self.decoders.append(UnicodeEscapeDecoder())
        if self.config.get("decoders", {}).get("utf16", True):
            self.decoders.append(Utf16Decoder())
        if self.config.get("decoders", {}).get("ascii85", True):
            self.decoders.append(Ascii85Decoder())
        if self.config.get("decoders", {}).get("raw_deflate", True):
            self.decoders.append(RawDeflateDecoder(max_decompressed))
        if self.config.get("decoders", {}).get("powershell_encoded_command", True):
            self.decoders.append(PowerShellEncodedCommandDecoder())
        if self.config.get("decoders", {}).get("javascript_escape", True):
            self.decoders.append(JavaScriptEscapeDecoder())
        if self.config.get("decoders", {}).get("javascript_emulation", True):
            self.decoders.append(JavaScriptEmulationDecoder())
        if self.config.get("decoders", {}).get("base58", True):
            self.decoders.append(Base58Decoder())
        if self.config.get("decoders", {}).get("base91", True):
            self.decoders.append(Base91Decoder())
        if self.config.get("decoders", {}).get("brotli", True):
            self.decoders.append(BrotliDecoder(max_decompressed))
        if self.config.get("decoders", {}).get("zstandard", True):
            self.decoders.append(ZstandardDecoder(max_decompressed))

        # Initialize off-by-default decoders (will be enabled by smart detection)
        self.uuencoder = UUDecoder(
            enabled=self.config.get("decoders", {}).get("uuencode", False)
        )
        self.asn1_decoder = ASN1Decoder(
            enabled=self.config.get("decoders", {}).get("asn1", False)
        )
        self.qp_decoder = QuotedPrintableDecoder(
            enabled=self.config.get("decoders", {}).get("quoted_printable", False)
        )
        self.base32_decoder = Base32Decoder(
            enabled=self.config.get("decoders", {}).get("base32", False)
        )
        # Remember the configured enablement so smart-detection changes made
        # during one run can be undone before the next (run_analysis resets to
        # this baseline). Decoders explicitly enabled via config must also be
        # registered here — previously they were constructed enabled but never
        # added to self.decoders, so the config flags had no effect.
        self._optional_decoder_baseline = [
            (self.uuencoder, self.uuencoder.enabled),
            (self.asn1_decoder, self.asn1_decoder.enabled),
            (self.qp_decoder, self.qp_decoder.enabled),
            (self.base32_decoder, self.base32_decoder.enabled),
        ]
        for decoder, enabled in self._optional_decoder_baseline:
            if enabled:
                self.decoders.append(decoder)

        # Initialize analyzers
        self.analyzers: List[Analyzer] = []
        structured_config = {
            "max_structured_artifacts": self.config.get("max_structured_artifacts", 32),
            "max_structured_total_size": self.config.get(
                "max_structured_total_size", 16 * 1024 * 1024
            ),
            "max_structured_artifact_size": self.config.get(
                "max_structured_artifact_size", 4 * 1024 * 1024
            ),
            "max_compression_ratio": self.config.get("max_compression_ratio", 100),
        }
        if self.config.get("analyzers", {}).get("email", True):
            self.analyzers.append(EmailAnalyzer(structured_config))
        if self.config.get("analyzers", {}).get("office", True):
            self.analyzers.append(OfficeAnalyzer(structured_config))
        if self.config.get("analyzers", {}).get("rtf", True):
            self.analyzers.append(RtfAnalyzer(structured_config))
        if self.config.get("analyzers", {}).get("script", True):
            self.analyzers.append(ScriptAnalyzer(structured_config))
        if self.config.get("analyzers", {}).get("lnk", True):
            self.analyzers.append(LnkAnalyzer())
        if self.config.get("analyzers", {}).get("msi", True):
            self.analyzers.append(MsiAnalyzer(structured_config))
        if self.config.get("analyzers", {}).get("onenote", True):
            self.analyzers.append(OneNoteAnalyzer(structured_config))
        if self.config.get("analyzers", {}).get("optional_archives", True):
            self.analyzers.append(OptionalArchiveAnalyzer(structured_config))
        if self.config.get("analyzers", {}).get("virtual_disk", True):
            self.analyzers.append(VirtualDiskAnalyzer(structured_config))
        if self.config.get("analyzers", {}).get("zip", True):
            zip_config = {
                "max_zip_files": self.config.get("max_zip_files", 25),
                "max_zip_total_size": self.config.get(
                    "max_zip_total_size", 10 * 1024 * 1024
                ),
                "max_zip_file_size": self.config.get(
                    "max_zip_file_size", 50 * 1024 * 1024
                ),
                "max_compression_ratio": self.config.get("max_compression_ratio", 100),
                "zip_passwords": self.config.get("zip_passwords", ["infected"]),
            }
            self.analyzers.append(ZipAnalyzer(zip_config))
        if self.config.get("analyzers", {}).get("tar", True):
            tar_config = {
                "max_tar_files": self.config.get("max_tar_files", 25),
                "max_tar_total_size": self.config.get(
                    "max_tar_total_size", 10 * 1024 * 1024
                ),
                "max_tar_file_size": self.config.get(
                    "max_tar_file_size", 50 * 1024 * 1024
                ),
                "max_compression_ratio": self.config.get("max_compression_ratio", 100),
            }
            self.analyzers.append(TarAnalyzer(tar_config))
        if self.config.get("analyzers", {}).get("pe", True):
            self.analyzers.append(PEAnalyzer())
        if self.config.get("analyzers", {}).get("elf", True):
            self.analyzers.append(ELFAnalyzer())
        if self.config.get("analyzers", {}).get("macho", True):
            self.analyzers.append(MachOAnalyzer())
        if self.config.get("analyzers", {}).get("dex", True):
            self.analyzers.append(DexAnalyzer())
        if self.config.get("analyzers", {}).get("x86_shellcode_emulation", True):
            self.analyzers.append(X86ShellcodeEmulationAnalyzer())
        if self.config.get("analyzers", {}).get("embedded_payload", True):
            self.analyzers.append(
                EmbeddedPayloadAnalyzer(
                    {
                        "max_carved_artifacts": self.config.get(
                            "max_carved_artifacts", 8
                        ),
                        "max_carved_artifact_size": self.config.get(
                            "max_carved_artifact_size", 4 * 1024 * 1024
                        ),
                        "max_carved_total_size": self.config.get(
                            "max_carved_total_size", 16 * 1024 * 1024
                        ),
                        "max_carve_scan_bytes": self.config.get(
                            "max_carve_scan_bytes", 4 * 1024 * 1024
                        ),
                        "min_carved_run_length": self.config.get(
                            "min_carved_run_length", 24
                        ),
                    }
                )
            )
        if self.config.get("analyzers", {}).get("steganography", True):
            media_config = {
                "max_media_artifacts": self.config.get("max_media_artifacts", 8),
                "max_media_total_size": self.config.get(
                    "max_media_total_size", 8 * 1024 * 1024
                ),
                "max_media_artifact_size": self.config.get(
                    "max_media_artifact_size", 4 * 1024 * 1024
                ),
                "max_lsb_carrier_bytes": self.config.get(
                    "max_lsb_carrier_bytes", 4 * 1024 * 1024
                ),
                "max_lsb_output_size": self.config.get(
                    "max_lsb_output_size", 1024 * 1024
                ),
            }
            self.analyzers.append(SteganographyAnalyzer(media_config))

        # Load plugins
        self.plugin_manager = PluginManager(
            execution_mode=str(self.config.get("plugin_execution_mode", "isolated")),
            offline=bool(self.config.get("plugin_offline", True)),
            timeout_seconds=int(self.config.get("plugin_timeout_seconds", 10)),
            max_input_bytes=int(
                self.config.get("plugin_max_input_bytes", 100 * 1024 * 1024)
            ),
            max_output_bytes=int(
                self.config.get("plugin_max_output_bytes", 16 * 1024 * 1024)
            ),
            max_memory_mb=int(self.config.get("plugin_max_memory_mb", 512)),
            max_children=int(self.config.get("plugin_max_children", 100)),
        )
        plugin_dirs = self.config.get("plugin_dirs", [])
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

        # Deterministic ordering across runs/environments. Decode-score ties
        # resolve to the first decoder tried, so this sort is what makes tie
        # resolution reproducible.
        try:
            self.decoders.sort(key=lambda d: getattr(d, "name", ""))
        except Exception:
            pass
        try:
            self.analyzers.sort(key=lambda a: getattr(a, "name", ""))
        except Exception:
            pass

        self.nodes: List[AnalysisNode] = []
        # Running set of node content hashes for O(1) dedup (rebuilding a set
        # from all prior nodes on every call was O(n^2)).
        self._seen_hashes: set = set()
        self._node_cap_reached: bool = False
        self._analysis_limitations: set[str] = set()

    def _emit_progress(
        self,
        stage: str,
        percent: int,
        message: str,
        **details: Any,
    ) -> None:
        if self.progress_callback is None:
            return
        event = {
            "stage": stage,
            "percent": max(0, min(100, int(percent))),
            "message": message,
            **details,
        }
        try:
            self.progress_callback(event)
        except Exception:
            logger.debug("Progress callback failed", exc_info=True)

    def _cancelled(self) -> bool:
        try:
            return bool(self.cancel_event is not None and self.cancel_event.is_set())
        except Exception:
            return False

    def analyze_blob(
        self,
        data: bytes,
        parent_id: Optional[int] = None,
        depth: int = 0,
        is_decoded_content: bool = False,
        artifact_name: Optional[str] = None,
        is_analyzer_metadata: bool = False,
        produced_by: Optional[str] = None,
        source_offset: Optional[int] = None,
    ) -> None:
        """Recursively analyze a blob of data with intelligent scoring and pruning."""
        if self._cancelled():
            self._analysis_limitations.add("analysis_cancelled")
            return
        # Global safety checks: wall-clock and memory bounds.
        if self._analysis_deadline_monotonic is not None:
            if time.monotonic() > self._analysis_deadline_monotonic:
                self._analysis_limitations.add("analysis_timeout_reached")
                logger.error("Analysis deadline exceeded; aborting further analysis")
                return
        if self.max_memory_mb and self.resource_manager.should_abort_due_to_memory(
            self.max_memory_mb
        ):
            self._analysis_limitations.add("memory_limit_reached")
            logger.error("Memory pressure; aborting further analysis")
            return

        # Safety checks
        if not data or len(data) == 0:
            logger.warning(f"Skipping empty data at depth {depth}")
            return

        # Hard depth limit as safety net
        if depth > self.MAX_RECURSION_DEPTH:
            self._analysis_limitations.add("depth_limit_reached")
            logger.warning(f"Max recursion depth reached at depth {depth}")
            return

        # Global node-count cap. This MUST apply to decoded/extracted content
        # too: is_decoded_content bypasses every score/count pruning rule below,
        # so without this hard stop a small crafted nested archive fans out to
        # millions of nodes (max_node_count is otherwise unenforced once you are
        # inside decoded content), exhausting memory well before the timeout.
        if len(self.nodes) >= self.pruning_engine.max_nodes:
            if not self._node_cap_reached:
                self._node_cap_reached = True
                self._analysis_limitations.add("node_limit_reached")
                logger.warning(
                    f"Max node count ({self.pruning_engine.max_nodes}) reached; "
                    "stopping further analysis"
                )
            return

        # For root node and decoded content, always analyze. For speculative branches, check pruning.
        if (
            not is_decoded_content
            and depth > 0
            and self.pruning_engine.should_prune_node(
                node_score=0.0,  # Will be calculated after analysis
                depth=depth,
                current_node_count=len(self.nodes),
                data_size=len(data),
                content_type="Unknown",  # Will be determined during analysis
                is_decoded_content=is_decoded_content,
            )
        ):
            logger.info(f"Pruning node at depth {depth} (pre-analysis check)")
            return

        node = AnalysisNode(data, parent_id, depth, "ANALYZE")
        node.id = len(self.nodes)
        node.artifact_name = artifact_name
        node.produced_by = produced_by
        node.source_offset = source_offset
        self.nodes.append(node)
        self._emit_progress(
            "analysis",
            min(85, 5 + int(80 * len(self.nodes) / self.pruning_engine.max_nodes)),
            f"Analyzing node {node.id}",
            node_id=node.id,
            depth=depth,
        )

        # Check for duplicate content (hash deduplication), O(1) via running set.
        if node.sha256 in self._seen_hashes:
            logger.info("Duplicate content detected, skipping analysis")
            node.pruned = True
            node.analysis_state = "duplicate"
            node.termination_reason = "Duplicate content already exists in the tree."
            return
        self._seen_hashes.add(node.sha256)

        # Analyzer-generated metadata (summaries, parsed headers) is authored
        # by Titan itself, not recovered from the input. It stays in the graph
        # so previews feed IOC extraction and reporting, but running decoders
        # or analyzers over it can only manufacture false-positive nodes.
        if is_analyzer_metadata:
            node.analysis_state = "terminal"
            node.termination_reason = (
                "Analyzer-generated metadata artifact; not fed back through "
                "decoders or analyzers."
            )
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
                        logger.info(
                            f"Enabled UUEncode decoder (confidence: {confidence:.2f})"
                        )
                elif decoder_name == "asn1":
                    self.asn1_decoder.enabled = True
                    if self.asn1_decoder not in self.decoders:
                        self.decoders.append(self.asn1_decoder)
                        logger.info(
                            f"Enabled ASN.1 decoder (confidence: {confidence:.2f})"
                        )
                elif decoder_name == "quoted_printable":
                    self.qp_decoder.enabled = True
                    if self.qp_decoder not in self.decoders:
                        self.decoders.append(self.qp_decoder)
                        logger.info(
                            f"Enabled QuotedPrintable decoder (confidence: {confidence:.2f})"
                        )
                elif decoder_name == "base32":
                    self.base32_decoder.enabled = True
                    if self.base32_decoder not in self.decoders:
                        self.decoders.append(self.base32_decoder)
                        logger.info(
                            f"Enabled Base32 decoder (confidence: {confidence:.2f})"
                        )
            # The appends above put newly-enabled decoders at the tail, which
            # would break the name-sorted order that decode-score tie
            # resolution relies on. Restore the invariant before scoring.
            self.decoders.sort(key=lambda d: getattr(d, "name", ""))

        # Composing passes (embedded-payload carving) run first and do not
        # consume the single analyzer slot below: a host file is still worth
        # analyzing as its own format after its embedded blobs are carved out.
        self._run_composing_analyzers(data, node, depth)
        if self._cancelled():
            self._analysis_limitations.add("analysis_cancelled")
            return

        # Prefer archive analyzers before heuristic decoders.
        # This avoids cases where a container format (e.g., ZIP) is "successfully"
        # decoded by something like XOR/ROT13, preventing extraction of embedded artifacts.
        for analyzer in self.analyzers:
            if self._cancelled():
                self._analysis_limitations.add("analysis_cancelled")
                return
            if getattr(analyzer, "composes", False):
                continue
            if analyzer.can_analyze(data):
                logger.info(f"Using analyzer: {analyzer.name}")
                started = time.monotonic()
                try:
                    with self.resource_manager.timeout_context(
                        self.analyzer_timeout_seconds,
                        operation_name=f"analyzer:{analyzer.name}",
                    ):
                        extracted = analyzer.analyze(data)
                    if extracted:  # Only proceed if extraction succeeded
                        node.method = f"ANALYZE_{analyzer.name}"
                        node.analysis_state = "extracted"
                        node.termination_reason = f"Extracted {len(extracted)} artifact(s) with {analyzer.name}."

                        # Calculate score for archive extraction
                        archive_score = self.scoring_engine.calculate_decode_score(
                            data,
                            b"".join(content for _, content in extracted),
                            analyzer.name,
                            depth,
                        )
                        node.decode_score = archive_score
                        node.decoder_used = analyzer.name

                        # Analyze each extracted file. Extracted content is
                        # never score-pruned (is_decoded_content=True); the
                        # depth limit and global node cap inside analyze_blob
                        # are what bound the fan-out.
                        metadata_names = getattr(
                            analyzer, "metadata_artifact_names", frozenset()
                        )
                        for name, content in extracted:
                            self.analyze_blob(
                                content,
                                node.id,
                                depth + 1,
                                is_decoded_content=True,
                                artifact_name=name,
                                is_analyzer_metadata=name in metadata_names,
                            )

                        if self.include_decision_trace:
                            self.decision_trace.append(
                                {
                                    "node_id": node.id,
                                    "type": "analyzer",
                                    "name": analyzer.name,
                                    "success": True,
                                    "duration_ms": int(
                                        (time.monotonic() - started) * 1000
                                    ),
                                    "extracted_count": len(extracted),
                                    "score": archive_score,
                                }
                            )
                        return  # Stop after successful analysis
                except Exception as e:
                    logger.error(f"Analyzer {analyzer.name} failed: {e}")
                    if self.include_decision_trace:
                        self.decision_trace.append(
                            {
                                "node_id": node.id,
                                "type": "analyzer",
                                "name": analyzer.name,
                                "success": False,
                                "duration_ms": int((time.monotonic() - started) * 1000),
                                "error": str(e),
                            }
                        )

        # Try decoders first with scoring
        best_score = 0.0
        best_decoder = None
        best_decoded = None

        for decoder in self.decoders:
            if self._cancelled():
                self._analysis_limitations.add("analysis_cancelled")
                return
            can_decode_result = decoder.can_decode(data)
            if can_decode_result:
                logger.debug(f"Trying decoder: {decoder.name}")
                started = time.monotonic()
                try:
                    with self.resource_manager.timeout_context(
                        self.decode_timeout_seconds,
                        operation_name=f"decoder:{decoder.name}",
                    ):
                        decoded, success = decoder.decode(data)
                except Exception as e:
                    if self.include_decision_trace:
                        self.decision_trace.append(
                            {
                                "node_id": node.id,
                                "type": "decoder",
                                "name": decoder.name,
                                "success": False,
                                "duration_ms": int((time.monotonic() - started) * 1000),
                                "error": str(e),
                            }
                        )
                    continue
                if success and decoded != data:
                    # Calculate score for this decoding
                    score = self.scoring_engine.calculate_decode_score(
                        data, decoded, decoder.name, depth
                    )
                    logger.debug(f"Decoder {decoder.name} score: {score:.3f}")

                    if self.include_decision_trace:
                        self.decision_trace.append(
                            {
                                "node_id": node.id,
                                "type": "decoder",
                                "name": decoder.name,
                                "success": True,
                                "duration_ms": int((time.monotonic() - started) * 1000),
                                "score": score,
                                "decoded_size": len(decoded) if decoded else 0,
                            }
                        )

                    # Keep track of best scoring decode. Ties resolve to the
                    # first decoder tried; self.decoders is sorted by name at
                    # init, so this is already the alphabetically-first one.
                    if score > best_score:
                        best_score = score
                        best_decoder = decoder.name
                        best_decoded = decoded
            else:
                logger.debug(f"Decoder {decoder.name} cannot decode this data")

        # Apply best scoring decode if it meets threshold
        if best_decoded and best_score >= self.pruning_engine.min_score_threshold:
            logger.info(f"Applying decoder: {best_decoder} (score: {best_score:.3f})")
            node.method = f"DECODE_{best_decoder}"
            node.decode_score = best_score
            node.decoder_used = best_decoder
            node.decoded_length = len(best_decoded)
            node.analysis_state = "decoded"
            node.termination_reason = (
                f"Applied {best_decoder} with confidence {best_score:.3f}."
            )

            # Continue analysis with decoded data
            self.analyze_blob(best_decoded, node.id, depth + 1, is_decoded_content=True)
            return  # Stop after successful decoding

        # No successful decoding or analysis
        logger.info(f"Leaf node reached at depth {depth} (score: {best_score:.3f})")
        node.analysis_state = "terminal"
        if best_decoder is not None:
            node.termination_reason = (
                f"Best candidate {best_decoder} scored {best_score:.3f}, below the "
                f"{self.pruning_engine.min_score_threshold:.3f} threshold."
            )
        else:
            node.termination_reason = (
                "No supported analyzer or decoder accepted the remaining payload."
            )
        if best_score < self.pruning_engine.min_score_threshold:
            node.pruned = True

    def _run_composing_analyzers(
        self, data: bytes, node: "AnalysisNode", depth: int
    ) -> None:
        """Run analyzers that add artifacts without claiming the node.

        Embedded-payload carving is orthogonal to format analysis: the host is
        still a script/document/archive after its encoded regions are carved
        out, so these passes run first and the main analyzer loop skips them.
        Each carved child records the producing pass and the byte offset it was
        recovered from, so provenance stays truthful even when a different
        analyzer later claims the parent.
        """
        for analyzer in self.analyzers:
            if not getattr(analyzer, "composes", False):
                continue
            if self._cancelled():
                return
            started = time.monotonic()
            try:
                with self.resource_manager.timeout_context(
                    self.analyzer_timeout_seconds,
                    operation_name=f"analyzer:{analyzer.name}",
                ):
                    payloads = analyzer.carve(data)
            except Exception as exc:
                logger.error(f"Analyzer {analyzer.name} failed: {exc}")
                if self.include_decision_trace:
                    self.decision_trace.append(
                        {
                            "node_id": node.id,
                            "type": "analyzer",
                            "name": analyzer.name,
                            "success": False,
                            "error": str(exc),
                        }
                    )
                continue

            if not payloads:
                continue

            node.analysis_state = "extracted"
            if node.method == "ANALYZE":
                node.method = f"ANALYZE_{analyzer.name}"
            node.termination_reason = (
                f"Carved {len(payloads)} embedded payload(s) with {analyzer.name}."
            )
            if self.include_decision_trace:
                self.decision_trace.append(
                    {
                        "node_id": node.id,
                        "type": "analyzer",
                        "name": analyzer.name,
                        "success": True,
                        "duration_ms": int((time.monotonic() - started) * 1000),
                        "extracted_count": len(payloads),
                    }
                )
            for payload in payloads:
                self.analyze_blob(
                    payload.data,
                    node.id,
                    depth + 1,
                    is_decoded_content=True,
                    artifact_name=payload.name,
                    produced_by=analyzer.name,
                    source_offset=payload.offset,
                )

    def _finalize_provenance(self) -> None:
        """Attach a first-class provenance record to every node.

        Each node's blob was produced by an operation on its parent (or is the
        root input). The record captures *why the node exists and how it was
        produced* — the producing decoder/analyzer, the parent hash it was
        derived from, the confidence (decode score), the offset/label where
        known, and a human-readable reason — enough for an analyst (or a court)
        to retrace the derivation from the root input to any artifact.
        """
        by_id = {n.id: n for n in self.nodes}
        for node in self.nodes:
            if node.parent is None:
                node.provenance = {
                    "origin": "input",
                    "produced_by": None,
                    "parent_id": None,
                    "parent_sha256": None,
                    "confidence": None,
                    "artifact_name": node.artifact_name,
                    "reason": "root input blob",
                }
                continue

            parent = by_id.get(node.parent)
            producer = getattr(parent, "decoder_used", None) if parent else None
            parent_method = getattr(parent, "method", "") if parent else ""
            if parent_method.startswith("ANALYZE_"):
                origin = "extract"
            elif parent_method.startswith("DECODE_"):
                origin = "decode"
            else:
                origin = "derive"
            confidence = getattr(parent, "decode_score", None) if parent else None

            # A composing pass names itself: the parent may have been claimed
            # by a different analyzer afterwards, and attributing a carved
            # region to that analyzer would misstate how it was recovered.
            if node.produced_by:
                producer = node.produced_by
                origin = "carve"
                confidence = None

            if node.artifact_name:
                reason = (
                    f"{origin} of artifact '{node.artifact_name}' from node "
                    f"{node.parent} via {producer}"
                )
            else:
                reason = f"{origin} from node {node.parent} via {producer}"
            if isinstance(confidence, (int, float)):
                reason += f" (confidence {confidence:.3f})"

            if node.source_offset is not None:
                reason += f" at offset 0x{node.source_offset:x}"

            node.provenance = {
                "origin": origin,
                "produced_by": producer,
                "parent_id": node.parent,
                "parent_sha256": getattr(parent, "sha256", None) if parent else None,
                "confidence": confidence,
                "artifact_name": node.artifact_name,
                "source_offset": node.source_offset,
                "reason": reason,
            }

    def _reset_optional_decoders(self) -> None:
        """Restore off-by-default decoders to their configured baseline.

        Smart detection enables these decoders mid-run and appends them to
        self.decoders; without a reset that state leaked into subsequent
        run_analysis() calls on the same engine, making results depend on what
        was analyzed earlier.
        """
        for decoder, enabled in self._optional_decoder_baseline:
            decoder.enabled = enabled
            if not enabled and decoder in self.decoders:
                self.decoders.remove(decoder)

    @staticmethod
    def _node_is_opaque(node: AnalysisNode) -> bool:
        """Return whether a terminal node still resembles encoded/opaque data."""
        if node.source_length == 0:
            return False
        if node.content_type != "Text":
            return True
        preview = node.content_preview.strip()
        if not preview:
            return True
        printable_ratio = sum(ch.isprintable() or ch.isspace() for ch in preview) / len(
            preview
        )
        if printable_ratio < 0.85:
            return True
        longest_token = max(preview.split(), key=len, default="")
        if len(longest_token) < 80:
            return False
        encoded_alphabet = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-<>"
        )
        encoded_ratio = sum(ch in encoded_alphabet for ch in longest_token) / len(
            longest_token
        )
        return encoded_ratio >= 0.95

    def _build_analysis_outcome(self, input_data: bytes) -> Dict[str, Any]:
        """Summarize whether analysis interpreted or stalled on the payload."""
        if not input_data:
            return {
                "status": "empty_input",
                "complete": False,
                "summary": "No input bytes were available for analysis.",
                "terminal_node_ids": [],
                "opaque_terminal_node_ids": [],
                "weak_decodes": [],
                "limitations": ["empty_input"],
            }

        parent_ids = {node.parent for node in self.nodes if node.parent is not None}
        terminal_nodes = [node for node in self.nodes if node.id not in parent_ids]
        opaque_nodes = [
            node
            for node in terminal_nodes
            if node.analysis_state in {"terminal", "duplicate"}
            and self._node_is_opaque(node)
        ]
        transformed_nodes = [
            node
            for node in self.nodes
            if node.analysis_state in {"decoded", "extracted"}
        ]

        weak_threshold = max(float(self.pruning_engine.min_score_threshold) * 8.0, 0.05)
        weak_decodes = [
            {
                "node_id": node.id,
                "decoder": node.decoder_used,
                "score": node.decode_score,
            }
            for node in transformed_nodes
            if node.decoder_used and 0.0 < float(node.decode_score) < weak_threshold
        ]

        limitations = sorted(self._analysis_limitations)

        if limitations:
            status = "limited"
            summary = (
                "Analysis stopped at a configured safety limit; the payload may be "
                "only partially interpreted."
            )
        elif opaque_nodes and transformed_nodes:
            status = "partial_decode"
            summary = (
                f"Applied {len(transformed_nodes)} transformation(s), then stopped "
                f"with {len(opaque_nodes)} unrecognized terminal payload(s)."
            )
        elif opaque_nodes:
            status = "unrecognized"
            summary = (
                "No supported analyzer or decoder could interpret the terminal payload."
            )
        elif transformed_nodes:
            status = "decoded"
            summary = (
                f"Completed {len(transformed_nodes)} transformation(s) and reached "
                "readable or recognized terminal content."
            )
        else:
            status = "analyzed"
            summary = (
                "Input was analyzed directly; no decoding transformation was needed."
            )

        return {
            "status": status,
            "complete": status in {"decoded", "analyzed"},
            "summary": summary,
            "terminal_node_ids": [node.id for node in terminal_nodes],
            "opaque_terminal_node_ids": [node.id for node in opaque_nodes],
            "weak_decodes": weak_decodes,
            "limitations": limitations,
        }

    def run_analysis(self, input_data: bytes) -> Dict[str, Any]:
        """Run full analysis on input data."""
        self._emit_progress("initializing", 1, "Initializing analysis")
        analysis_id = str(uuid.uuid4())
        started_wall = datetime.now(timezone.utc)
        self._analysis_started_monotonic = time.monotonic()
        self._analysis_deadline_monotonic = (
            self._analysis_started_monotonic + self.analysis_timeout_seconds
            if self.analysis_timeout_seconds
            else None
        )

        self.nodes = []
        self._seen_hashes = set()
        self._node_cap_reached = False
        self._analysis_limitations = set()
        self.decision_trace = []
        self._reset_optional_decoders()
        self.analyze_blob(input_data, None, 0)
        self._emit_progress("provenance", 88, "Finalizing artifact provenance")
        self._finalize_provenance()

        finished_wall = datetime.now(timezone.utc)
        duration_ms = int(
            (time.monotonic() - (self._analysis_started_monotonic or 0)) * 1000
        )

        # Extract IOCs from every node's full content, not just Text-classified
        # ones. Malware routinely embeds C2 URLs/IPs in otherwise-binary content
        # (config blobs, shellcode, a readable URL followed by binary padding),
        # which the Text-only filter silently dropped. Scanning content_preview
        # dropped them again: the preview is a 2KB reporting excerpt, so an
        # indicator past byte 2000 of any artifact was invisible to the IOC
        # stage even though the bytes were retained. The regexes are specific
        # enough that binary noise contributes essentially no false positives
        # (URLs need "http://", IPs are ipaddress-validated dotted quads).
        all_text = "\n".join(self._ioc_scan_texts())

        report: Dict[str, Any] = {
            "meta": {
                "tool": "Titan Decoder Engine",
                "version": TITAN_VERSION,
                "schema_version": SCHEMA_VERSION,
                "analysis_id": analysis_id,
                "started_at": started_wall.isoformat(),
                "finished_at": finished_wall.isoformat(),
                "duration_ms": duration_ms,
            },
            "node_count": len(self.nodes),
            "nodes": [node.to_dict() for node in self.nodes],
            "iocs": extract_iocs(all_text),
        }

        report["analysis_outcome"] = self._build_analysis_outcome(input_data)

        report["run_manifest"] = self._build_run_manifest()

        if self.include_decision_trace:
            report["decision_trace"] = self.decision_trace

        self._emit_progress(
            "core_complete",
            90,
            "Core analysis complete" if not self._cancelled() else "Analysis cancelled",
            node_count=len(self.nodes),
        )

        return report

    def _ioc_scan_texts(self) -> List[str]:
        """Return per-node text for IOC extraction, bounded per node.

        Prefers the retained payload over ``content_preview`` so indicators are
        recovered from the whole artifact rather than its 2KB reporting
        excerpt. ``max_ioc_scan_bytes`` caps each node independently, which
        keeps the joined buffer proportional to the node cap instead of to
        total decoded volume. Truncation is applied on a byte boundary, so an
        indicator straddling the cap is dropped rather than half-reported.
        """
        texts: List[str] = []
        for node in self.nodes:
            data = getattr(node, "_data", None)
            if isinstance(data, (bytes, bytearray)) and self.max_ioc_scan_bytes:
                text = bytes(data[: self.max_ioc_scan_bytes]).decode(
                    "utf-8", errors="ignore"
                )
            else:
                text = node.content_preview
            if text:
                texts.append(text)
        return texts

    def artifact_payloads(self) -> List[tuple[int, bytes]]:
        """Return raw node payloads for in-process scanners, never serialization."""
        return [
            (int(node.id), node._data)
            for node in self.nodes
            if node.id is not None and isinstance(node._data, bytes)
        ]

    def _build_run_manifest(self) -> Dict[str, Any]:
        """Build a reproducible manifest describing how the run was configured."""

        # Config snapshot (redact known secrets).
        cfg = copy.deepcopy(getattr(self.config, "_config", {}))
        if isinstance(cfg, dict) and cfg.get("virustotal_api_key"):
            cfg["virustotal_api_key"] = "[REDACTED]"
        if isinstance(cfg, dict) and "zip_passwords" in cfg:
            passwords = cfg.get("zip_passwords")
            password_count = len(passwords) if isinstance(passwords, list) else 1
            cfg["zip_passwords"] = ["[REDACTED]"] * min(password_count, 8)

        decoder_names = []
        for d in self.decoders:
            name = getattr(d, "name", None)
            if name:
                decoder_names.append(name)

        analyzer_names = []
        for a in self.analyzers:
            name = getattr(a, "name", None)
            if name:
                analyzer_names.append(name)

        # Stable unique lists.
        decoder_names = sorted(set(decoder_names))
        analyzer_names = sorted(set(analyzer_names))

        plugin_info = {}
        try:
            plugin_info = self.plugin_manager.get_plugin_info()
        except Exception:
            plugin_info = {}

        return {
            "tool": {
                "name": "Titan Decoder Engine",
                "version": TITAN_VERSION,
                "schema_version": SCHEMA_VERSION,
            },
            "limits": {
                "analysis_timeout_seconds": self.analysis_timeout_seconds,
                "decode_timeout_seconds": self.decode_timeout_seconds,
                "analyzer_timeout_seconds": self.analyzer_timeout_seconds,
                "max_memory_mb": self.max_memory_mb,
                "max_recursion_depth": self.MAX_RECURSION_DEPTH,
                "max_node_count": self.config.get("max_node_count", 100),
                "min_score_threshold": self.config.get("min_score_threshold", 0.01),
                "max_data_size": self.config.get("max_data_size", 50 * 1024 * 1024),
            },
            "components": {
                "decoders": decoder_names,
                "analyzers": analyzer_names,
                "plugins": plugin_info,
            },
            "effective_config": cfg,
            "environment": {
                "python": sys.version.split(" ")[0],
                "platform": platform.platform(),
            },
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
