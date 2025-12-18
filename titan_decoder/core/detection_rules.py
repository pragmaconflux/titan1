"""Correlation rules engine with starter detection rules.

Provides a library of behavioral detection rules that run against the analysis
graph and IOCs to flag suspicious patterns commonly seen in malware.
"""

from __future__ import annotations

from typing import Dict, Any, List, Callable
import logging

logger = logging.getLogger(__name__)


class DetectionRule:
    """A single detection rule."""

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: str,
        detect_fn: Callable,
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity  # low, medium, high, critical
        self.detect_fn = detect_fn

    def evaluate(self, report: Dict[str, Any], iocs: Dict[str, Any]) -> bool:
        """Evaluate the rule against a report."""
        try:
            return self.detect_fn(report, iocs)
        except Exception as e:
            logger.error(f"Rule {self.rule_id} evaluation failed: {e}")
            return False


class CorrelationRulesEngine:
    """Correlation rules library with starter detection rules."""

    def __init__(self):
        self.rules: List[DetectionRule] = []
        self._load_starter_rules()

    def _load_starter_rules(self):
        """Load built-in starter detection rules."""

        # Rule 1: Deep Base64 nesting (common in obfuscated scripts)
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-001",
                name="Deep Base64 Nesting",
                description="Multiple layers of Base64 encoding detected (3+ levels)",
                severity="medium",
                detect_fn=lambda report, iocs: self._detect_deep_base64(report),
            )
        )

        # Rule 2: Suspicious Office macro patterns
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-002",
                name="Office Macro with Network IOCs",
                description="OLE file with embedded content and network indicators",
                severity="high",
                detect_fn=lambda report, iocs: self._detect_office_macro_network(
                    report, iocs
                ),
            )
        )

        # Rule 3: Signed binary spawning script host (LOLBin pattern)
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-003",
                name="LOLBin Script Execution Pattern",
                description="Content suggests legitimate binary executing scripts",
                severity="medium",
                detect_fn=lambda report, iocs: self._detect_lolbin_pattern(report),
            )
        )

        # Rule 4: High entropy data with low decoding success
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-004",
                name="Encrypted or Packed Payload",
                description="High entropy data with minimal successful decoding",
                severity="low",
                detect_fn=lambda report, iocs: self._detect_encrypted_payload(report),
            )
        )

        # Rule 5: Multiple IOC types present
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-005",
                name="Multi-Stage Infrastructure",
                description="Multiple IOC types suggest multi-stage attack infrastructure",
                severity="high",
                detect_fn=lambda report, iocs: self._detect_multistage_infra(
                    report, iocs
                ),
            )
        )

        # Rule 6: XOR encoding with network indicators
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-006",
                name="XOR Obfuscation with C2",
                description="XOR-encoded content containing network IOCs",
                severity="high",
                detect_fn=lambda report, iocs: self._detect_xor_with_network(
                    report, iocs
                ),
            )
        )

        # Rule 7: PDF with embedded executable content
        self.rules.append(
            DetectionRule(
                rule_id="TITAN-007",
                name="Malicious PDF",
                description="PDF containing PE or executable-like content",
                severity="critical",
                detect_fn=lambda report, iocs: self._detect_malicious_pdf(report),
            )
        )

        logger.info(f"Loaded {len(self.rules)} correlation rules")

    def _detect_deep_base64(self, report: Dict[str, Any]) -> bool:
        """Detect multiple layers of Base64 encoding."""
        nodes = report.get("nodes", [])
        max_depth = 0
        base64_chain = 0

        for node in nodes:
            decoder = node.get("decoder_used", "") or ""
            if "base64" in decoder.lower():
                base64_chain += 1
                max_depth = max(max_depth, node.get("depth", 0))

        return base64_chain >= 3 or max_depth >= 4

    def _detect_office_macro_network(
        self, report: Dict[str, Any], iocs: Dict[str, Any]
    ) -> bool:
        """Detect Office documents with macros and network IOCs."""
        nodes = report.get("nodes", [])
        has_ole = any("OLE" in node.get("method", "") for node in nodes)
        has_network = bool(
            iocs.get("urls") or iocs.get("ipv4_public") or iocs.get("domains")
        )

        return has_ole and has_network

    def _detect_lolbin_pattern(self, report: Dict[str, Any]) -> bool:
        """Detect LOLBin execution patterns."""
        nodes = report.get("nodes", [])
        lolbins = [
            "powershell",
            "cmd.exe",
            "wscript",
            "cscript",
            "mshta",
            "rundll32",
            "regsvr32",
        ]

        text = "\n".join(node.get("content_preview", "").lower() for node in nodes)

        return any(lolbin in text for lolbin in lolbins)

    def _detect_encrypted_payload(self, report: Dict[str, Any]) -> bool:
        """Detect high entropy payloads with minimal decoding."""
        nodes = report.get("nodes", [])

        if not nodes:
            return False

        root = nodes[0]
        root_entropy = root.get("entropy", 0)

        # High entropy at root with few successful decodes
        successful_decodes = sum(1 for n in nodes if n.get("decode_score", 0) > 0.5)

        return root_entropy > 7.5 and len(nodes) < 5 and successful_decodes <= 1

    def _detect_multistage_infra(
        self, report: Dict[str, Any], iocs: Dict[str, Any]
    ) -> bool:
        """Detect multi-stage attack infrastructure."""
        ioc_types = sum(
            [
                bool(iocs.get("urls")),
                bool(iocs.get("ipv4_public")),
                bool(iocs.get("domains")),
                bool(iocs.get("emails")),
            ]
        )

        return ioc_types >= 3

    def _detect_xor_with_network(
        self, report: Dict[str, Any], iocs: Dict[str, Any]
    ) -> bool:
        """Detect XOR encoding with network indicators."""
        nodes = report.get("nodes", [])
        has_xor = any("xor" in node.get("decoder_used", "").lower() for node in nodes)
        has_network = bool(iocs.get("urls") or iocs.get("ipv4_public"))

        return has_xor and has_network

    def _detect_malicious_pdf(self, report: Dict[str, Any]) -> bool:
        """Detect PDFs with embedded executables."""
        nodes = report.get("nodes", [])
        has_pdf = any("PDF" in node.get("method", "") for node in nodes)

        # Look for PE/ELF signatures in decoded content
        for node in nodes:
            preview = node.get("content_preview", "")
            if "MZ" in preview or "ELF" in preview:
                return has_pdf

        return False

    def evaluate_all(
        self, report: Dict[str, Any], iocs: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Evaluate all rules and return matches."""
        detections = []

        for rule in self.rules:
            if rule.evaluate(report, iocs):
                detections.append(
                    {
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity,
                    }
                )
                logger.info(f"Detection: {rule.name} ({rule.rule_id})")

        return detections

    def add_custom_rule(self, rule: DetectionRule):
        """Add a custom detection rule."""
        self.rules.append(rule)
        logger.info(f"Added custom rule: {rule.name}")
