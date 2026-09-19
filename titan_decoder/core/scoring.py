"""
Scoring and pruning system for Titan Decoder Engine.

This module provides intelligent scoring functions to evaluate the quality
and relevance of decoding operations, enabling smart pruning of analysis paths.
"""

from typing import Dict, Any, Optional
import re

from ..utils.helpers import entropy, looks_like_structured_binary


class ScoringEngine:
    """Unified scoring system for decoder evaluation and pruning."""

    # Scoring weights (configurable)
    ENTROPY_WEIGHT = 0.4
    PRINTABLE_WEIGHT = 0.3
    STRUCTURE_WEIGHT = 0.2
    COST_WEIGHT = 0.1

    # Decoder cost rankings (lower = cheaper). Keys MUST match each decoder's
    # ``.name`` exactly, otherwise the lookup silently falls back to the default
    # cost: "Lzma"/"Rot13" never matched the real names "LZMA"/"ROT13", and
    # "ZLIB" was missing entirely, so those three were mis-costed.
    DECODER_COSTS = {
        "Base64": 1,
        "RecursiveBase64": 2,
        "Base64URL": 2,
        "PEM": 2,
        "Gzip": 3,
        "Bz2": 3,
        "LZMA": 4,
        "ZLIB": 3,
        "Hex": 2,
        "ROT13": 1,
        "UTF16": 2,
        "XOR": 5,  # Expensive: brute force + repeating-key column analysis
        "ZIP": 3,
        "TAR": 3,
    }

    # Structural patterns that indicate meaningful decoding.
    # Two-byte magics (MZ, BZ) are anchored to the start of the data:
    # unanchored they match those letter pairs in ordinary text, inflating
    # scores for meaningless "decodes".
    STRUCTURE_PATTERNS = [
        re.compile(rb"\x7fELF"),  # ELF header
        re.compile(rb"\AMZ"),  # PE header (anchored)
        re.compile(rb"PK\x03\x04"),  # ZIP header
        re.compile(rb"\x1f\x8b"),  # GZIP header
        re.compile(rb"\ABZ"),  # BZIP2 header (anchored)
        re.compile(rb"#!/.*"),  # Shebang
        re.compile(rb"<\?xml"),  # XML declaration
        re.compile(rb'^\s*{\s*"'),  # JSON start
        re.compile(rb"^\s*\[\s*"),  # JSON array
        re.compile(rb"^[a-zA-Z_][a-zA-Z0-9_]*\s*="),  # Variable assignment
        re.compile(rb"import\s+\w+"),  # Import statement
        re.compile(rb"function\s+\w+"),  # Function definition
        re.compile(rb"class\s+\w+"),  # Class definition
        # Network / command indicators: a decode that reveals a URL or a shell/
        # PowerShell invocation is meaningful even when it yields no entropy
        # reduction or printable gain. Single-byte XOR is a bijection, so a
        # printable-ASCII-keyed config (e.g. a C2 URL) scores 0 on those
        # components; rewarding these markers lets the reveal clear the score
        # threshold and be followed instead of dropped.
        re.compile(rb"https?://"),  # URL
        re.compile(rb"[Pp]ower[Ss]hell"),  # PowerShell
        re.compile(rb"cmd\.exe"),  # cmd
        re.compile(rb"/bin/(?:ba)?sh"),  # POSIX shell
    ]

    @classmethod
    def calculate_decode_score(
        cls,
        original_data: bytes,
        decoded_data: bytes,
        decoder_name: str,
        depth: int = 0,
    ) -> float:
        """
        Calculate a comprehensive score for a decoding operation.

        Returns a score between 0.0 and 1.0, where higher scores indicate
        more successful/relevant decoding operations.
        """
        if not decoded_data or decoded_data == original_data:
            return 0.0

        # Component scores
        entropy_score = cls._entropy_reduction_score(original_data, decoded_data)
        printable_score = cls._printable_ratio_gain(original_data, decoded_data)
        structure_score = cls._structural_emergence_score(decoded_data)
        cost_score = cls._decoder_cost_score(decoder_name, depth)

        # Weighted combination
        total_score = (
            cls.ENTROPY_WEIGHT * entropy_score
            + cls.PRINTABLE_WEIGHT * printable_score
            + cls.STRUCTURE_WEIGHT * structure_score
            + cls.COST_WEIGHT * cost_score
        )

        # Depth penalty (deeper decodings are generally less reliable)
        depth_penalty = max(0.1, 1.0 - (depth * 0.1))

        plausibility = cls._output_plausibility(original_data, decoded_data)

        return min(1.0, total_score * depth_penalty * plausibility)

    # A decode that turns clean text into unrecognizable binary keeps this
    # share of its score. It is demoted against competing interpretations
    # rather than discarded, so the node still appears when nothing else
    # claims the input.
    IMPLAUSIBLE_OUTPUT_RETENTION = 0.25

    @classmethod
    def _output_plausibility(cls, original: bytes, decoded: bytes) -> float:
        """Penalize decodes that destroy printable structure for nothing.

        Entropy reduction and printable *gain* both measure improvement, so
        when the input is already fully printable neither can separate a good
        decode from a bad one -- both score zero and the winner is decided by
        decoder cost alone. That let Base64 beat Hex on an even-length hex
        string, which both decoders accept: Hex returned
        ``Hex calibration payload!`` and lost to high-entropy noise.

        Improvement alone is not enough; destroying structure has to cost
        something. Output that carries a known signature or stays printable is
        unaffected, so base64-wrapped executables and archives keep their
        scores -- the penalty applies only when readable input becomes
        unreadable output that nothing recognizes.
        """
        if not original or not decoded:
            return 1.0

        def printable_ratio(data: bytes) -> float:
            sample = data[:8192]
            if not sample:
                return 0.0
            return sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126) / len(
                sample
            )

        if printable_ratio(original) < 0.9:
            return 1.0  # Input was not readable to begin with.
        if printable_ratio(decoded) >= 0.5:
            return 1.0  # Output is still substantially readable.
        if looks_like_structured_binary(decoded):
            return 1.0  # Recognizable container, executable, or compressed stream.
        return cls.IMPLAUSIBLE_OUTPUT_RETENTION

    @classmethod
    def _entropy_reduction_score(cls, original: bytes, decoded: bytes) -> float:
        """Score based on entropy reduction (more structured = better)."""
        if not original or not decoded:
            return 0.0

        original_entropy = entropy(original)
        decoded_entropy = entropy(decoded)

        # Entropy reduction indicates more structured data
        if original_entropy == 0:
            return 0.5  # Neutral score

        reduction = (original_entropy - decoded_entropy) / original_entropy
        return max(0.0, min(1.0, reduction))

    @classmethod
    def _printable_ratio_gain(cls, original: bytes, decoded: bytes) -> float:
        """Score based on increase in printable characters."""

        def printable_ratio(data: bytes) -> float:
            if not data:
                return 0.0
            printable = sum(1 for b in data if 32 <= b <= 126)
            return printable / len(data)

        original_ratio = printable_ratio(original)
        decoded_ratio = printable_ratio(decoded)

        # Gain in printable characters
        gain = decoded_ratio - original_ratio
        return max(0.0, min(1.0, gain * 2))  # Scale for better sensitivity

    @classmethod
    def _structural_emergence_score(cls, decoded: bytes) -> float:
        """Score based on emergence of structural patterns."""
        if not decoded:
            return 0.0

        score = 0.0
        decoded_str = decoded.decode("utf-8", errors="ignore")

        # Check for structural patterns
        for pattern in cls.STRUCTURE_PATTERNS:
            if pattern.search(decoded):
                score += 0.2  # Each pattern found adds to score

        # Bonus for common file signatures
        if decoded.startswith(b"#!/"):  # Scripts
            score += 0.3
        if b"import " in decoded or b"from " in decoded:  # Python imports
            score += 0.3
        if b"function" in decoded or b"def " in decoded:  # Functions
            score += 0.2

        # Check for JSON/XML structure
        if decoded_str.strip().startswith(("{", "[")):
            try:
                import json

                json.loads(decoded_str)
                score += 0.4  # Valid JSON
            except Exception:
                score += 0.1  # Looks like JSON but invalid

        return min(1.0, score)

    @classmethod
    def _decoder_cost_score(cls, decoder_name: str, depth: int) -> float:
        """Score based on decoder cost (cheaper = better)."""
        base_cost = cls.DECODER_COSTS.get(decoder_name, 3)  # Default medium cost

        # Cost increases with depth (deeper operations are riskier)
        depth_multiplier = 1.0 + (depth * 0.1)

        # Normalize to 0-1 scale (lower cost = higher score)
        normalized_cost = min(5.0, base_cost * depth_multiplier)
        return 1.0 - (normalized_cost / 5.0)


class PruningEngine:
    """Centralized pruning policy for analysis trees with advanced rules."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.max_nodes = self.config.get("max_node_count", 100)
        # Default must match Config.DEFAULT_CONFIG (0.01); a mismatched
        # fallback here silently changes pruning for direct constructor use.
        self.min_score_threshold = self.config.get("min_score_threshold", 0.01)
        self.max_depth = self.config.get("max_recursion_depth", 5)

        # Pruning policy toggles (each one gates a rule in should_prune_node).
        self.policies = {
            "enable_quality_pruning": self.config.get("enable_quality_pruning", True),
            "enable_resource_pruning": self.config.get("enable_resource_pruning", True),
            "enable_depth_based_limits": self.config.get(
                "enable_depth_based_limits", True
            ),
        }

        # Depth-based node limits (more restrictive at deeper levels)
        self.depth_limits = {
            0: self.max_nodes,  # Root level
            1: 20,  # First decode
            2: 15,  # Second level
            3: 10,  # Third level
            4: 5,  # Fourth level
            5: 3,  # Fifth level (max depth)
        }

    def should_prune_node(
        self,
        node_score: float,
        depth: int,
        current_node_count: int,
        data_size: int,
        content_type: str = "Unknown",
        is_decoded_content: bool = False,
    ) -> bool:
        """Enhanced pruning decision with multiple policy layers."""

        # Always allow decoded content to be analyzed (don't prune successful decodes)
        if is_decoded_content:
            return False

        # Depth limit
        if depth > self.max_depth:
            return True

        # Depth-based node count limits
        if self.policies["enable_depth_based_limits"]:
            depth_limit = self.depth_limits.get(depth, 3)
            if current_node_count >= depth_limit:
                return True

        # Global node count limit
        if current_node_count >= self.max_nodes:
            return True

        # Score threshold
        if node_score < self.min_score_threshold:
            return True

        # Size sanity check (prevent zip bombs, etc.)
        max_size = self.config.get("max_data_size", 50 * 1024 * 1024)  # 50MB default
        if data_size > max_size:
            return True

        # Quality-based pruning
        if self.policies["enable_quality_pruning"]:
            if self._is_low_quality_content(node_score, content_type, depth):
                return True

        # Resource-aware pruning
        if self.policies["enable_resource_pruning"]:
            if self._is_resource_intensive(data_size, depth):
                return True

        return False

    def _is_low_quality_content(
        self, score: float, content_type: str, depth: int
    ) -> bool:
        """Determine if content is low quality and should be pruned."""
        # Very low scores at any depth
        if score < 0.01:
            return True

        # Binary content at deep levels (likely not meaningful)
        if depth > 2 and content_type == "Binary" and score < 0.1:
            return True

        # Text content with very low entropy (might be padding/junk)
        if content_type == "Text" and score < 0.05:
            return True

        return False

    def _is_resource_intensive(self, data_size: int, depth: int) -> bool:
        """Check if processing this data would be too resource intensive."""
        # Large data at deep recursion levels
        if depth > 3 and data_size > 1024 * 1024:  # 1MB
            return True

        # Very large data even at shallow levels
        if data_size > 10 * 1024 * 1024:  # 10MB
            return True

        return False
