"""
Scoring and pruning system for Titan Decoder Engine.

This module provides intelligent scoring functions to evaluate the quality
and relevance of decoding operations, enabling smart pruning of analysis paths.
"""

from typing import Dict, Any, Optional
import re
import math


class ScoringEngine:
    """Unified scoring system for decoder evaluation and pruning."""

    # Scoring weights (configurable)
    ENTROPY_WEIGHT = 0.4
    PRINTABLE_WEIGHT = 0.3
    STRUCTURE_WEIGHT = 0.2
    COST_WEIGHT = 0.1

    # Decoder cost rankings (lower = cheaper)
    DECODER_COSTS = {
        "Base64": 1,
        "RecursiveBase64": 2,
        "Gzip": 3,
        "Bz2": 3,
        "Lzma": 4,
        "Hex": 2,
        "Rot13": 1,
        "XOR": 5,  # Expensive due to brute force
        "ZIP": 3,
        "TAR": 3,
    }

    # Structural patterns that indicate meaningful decoding
    STRUCTURE_PATTERNS = [
        re.compile(rb'\x7fELF'),  # ELF header
        re.compile(rb'MZ'),      # PE header
        re.compile(rb'PK\x03\x04'),  # ZIP header
        re.compile(rb'\x1f\x8b'),     # GZIP header
        re.compile(rb'BZ'),          # BZIP2 header
        re.compile(rb'#!/.*'),       # Shebang
        re.compile(rb'<?xml'),       # XML
        re.compile(rb'^\s*{\s*"'),    # JSON start
        re.compile(rb'^\s*\[\s*'),    # JSON array
        re.compile(rb'^[a-zA-Z_][a-zA-Z0-9_]*\s*='),  # Variable assignment
        re.compile(rb'import\s+\w+'),  # Import statement
        re.compile(rb'function\s+\w+'),  # Function definition
        re.compile(rb'class\s+\w+'),     # Class definition
    ]

    @classmethod
    def calculate_decode_score(
        cls,
        original_data: bytes,
        decoded_data: bytes,
        decoder_name: str,
        depth: int = 0
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
            cls.ENTROPY_WEIGHT * entropy_score +
            cls.PRINTABLE_WEIGHT * printable_score +
            cls.STRUCTURE_WEIGHT * structure_score +
            cls.COST_WEIGHT * cost_score
        )

        # Depth penalty (deeper decodings are generally less reliable)
        depth_penalty = max(0.1, 1.0 - (depth * 0.1))

        return min(1.0, total_score * depth_penalty)

    @classmethod
    def _entropy_reduction_score(cls, original: bytes, decoded: bytes) -> float:
        """Score based on entropy reduction (more structured = better)."""
        if not original or not decoded:
            return 0.0

        def calculate_entropy(data: bytes) -> float:
            if not data:
                return 0.0
            freq = {}
            for b in data:
                freq[b] = freq.get(b, 0) + 1
            entropy = 0.0
            for count in freq.values():
                p = count / len(data)
                entropy -= p * math.log2(p) if p > 0 else 0
            return entropy

        original_entropy = calculate_entropy(original)
        decoded_entropy = calculate_entropy(decoded)

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
        decoded_str = decoded.decode('utf-8', errors='ignore')

        # Check for structural patterns
        for pattern in cls.STRUCTURE_PATTERNS:
            if pattern.search(decoded):
                score += 0.2  # Each pattern found adds to score

        # Bonus for common file signatures
        if decoded.startswith(b'#!/'):  # Scripts
            score += 0.3
        if b'import ' in decoded or b'from ' in decoded:  # Python imports
            score += 0.3
        if b'function' in decoded or b'def ' in decoded:  # Functions
            score += 0.2

        # Check for JSON/XML structure
        if decoded_str.strip().startswith(('{', '[')):
            try:
                import json
                json.loads(decoded_str)
                score += 0.4  # Valid JSON
            except:
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
    """Centralized pruning policy for analysis trees."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.max_nodes = self.config.get('max_node_count', 100)
        self.min_score_threshold = self.config.get('min_score_threshold', 0.1)
        self.max_depth = self.config.get('max_recursion_depth', 5)

    def should_prune_node(
        self,
        node_score: float,
        depth: int,
        current_node_count: int,
        data_size: int
    ) -> bool:
        """Determine if a node should be pruned from analysis."""

        # Depth limit
        if depth > self.max_depth:
            return True

        # Node count limit
        if current_node_count >= self.max_nodes:
            return True

        # Score threshold
        if node_score < self.min_score_threshold:
            return True

        # Size sanity check (prevent zip bombs, etc.)
        max_size = self.config.get('max_data_size', 50 * 1024 * 1024)  # 50MB default
        if data_size > max_size:
            return True

        return False

    def should_prune_path(
        self,
        path_scores: list,
        total_nodes: int
    ) -> bool:
        """Determine if an entire analysis path should be pruned."""

        # If path has too many low-score nodes, prune it
        low_score_ratio = sum(1 for s in path_scores if s < 0.2) / len(path_scores)
        if low_score_ratio > 0.7:  # 70%+ low scores
            return True

        # If path is getting too long without good scores
        recent_scores = path_scores[-3:]  # Last 3 nodes
        if len(recent_scores) >= 3 and all(s < 0.3 for s in recent_scores):
            return True

        return False