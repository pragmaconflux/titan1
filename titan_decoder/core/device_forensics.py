"""Lightweight device forensics and attribution helpers.

This module keeps everything on the **defensive/forensic** side. It extracts
observable indicators from already-decoded content (nodes) to help law
enforcement or responders connect attacks across incidents. No offensive
capabilities are included.
"""

from __future__ import annotations

import re
from typing import Dict, List, Any, Iterable


class ForensicsEngine:
    """Extracts device, VM, and burner indicators from analysis reports.

    The engine works on the output of ``TitanEngine.run_analysis`` (a dict with
    a ``nodes`` list). It scans the textual previews for common artifacts:
    - VM/platform fingerprints (VirtualBox, VMware, KVM, Hyper-V)
    - Mobile identifiers (IMEI, IMSI, ICCID)
    - Burner heuristics (generic hostnames, fresh installs)
    - Timezone and language hints
    The output is a summary that can be shared with investigators.
    """

    VM_SIGNATURES = {
        "virtualbox": ["VirtualBox", "vbox", "vmmouse"],
        "vmware": ["VMware", "vmxnet", "vmtools"],
        "hyperv": ["Hyper-V", "hv_kvp", "VMBus"],
        "kvm": ["KVM", "virtio", "qemu"],
        "xen": ["Xen", "xenbus"],
    }

    BURNER_HOST_PATTERNS = [
        r"DESKTOP-[A-Z0-9]{5,}",
        r"LAPTOP-[A-Z0-9]{5,}",
        r"WIN-[A-Z0-9]{5,}",
    ]

    TIMEZONE_HINTS = [
        "UTC", "GMT", "PST", "PDT", "MST", "MDT",
        "CST", "CDT", "EST", "EDT",
    ]

    def __init__(self, max_preview_bytes: int = 200_000) -> None:
        self.max_preview_bytes = max_preview_bytes
        self.imei_re = re.compile(r"\b\d{15}\b")
        self.imsi_re = re.compile(r"\b\d{5,15}\b")
        self.iccid_re = re.compile(r"\b89\d{15,19}\b")
        self.ip_re = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
        )

    def analyze(self, analysis_report: Dict[str, Any]) -> Dict[str, Any]:
        nodes = analysis_report.get("nodes", [])
        text_corpus = self._gather_text(nodes)

        vm_hits = self._detect_vm(text_corpus)
        mobile_ids = self._detect_mobile_ids(text_corpus)
        burner = self._detect_burner_patterns(text_corpus)
        timezone_hints = self._detect_timezones(text_corpus)
        hardware = self._detect_hardware(text_corpus)
        ips = self._detect_ips(text_corpus)

        recommendations = self._build_recommendations(vm_hits, burner, mobile_ids)

        return {
            "vm": {
                "hits": vm_hits,
                "detected": bool(vm_hits),
            },
            "mobile_ids": mobile_ids,
            "burner": burner,
            "timezone_hints": timezone_hints,
            "hardware_hints": hardware,
            "network_indicators": {"ips": ips},
            "recommendations": recommendations,
        }

    def _gather_text(self, nodes: Iterable[Dict[str, Any]]) -> str:
        parts: List[str] = []
        total = 0
        for node in nodes:
            preview = node.get("content_preview", "")
            if preview:
                preview_bytes = preview.encode("utf-8", errors="ignore")
                if total + len(preview_bytes) > self.max_preview_bytes:
                    remaining = self.max_preview_bytes - total
                    parts.append(preview_bytes[:remaining].decode("utf-8", errors="ignore"))
                    break
                parts.append(preview)
                total += len(preview_bytes)
        return "\n".join(parts)

    def _detect_vm(self, text: str) -> List[str]:
        hits: List[str] = []
        lowered = text.lower()
        for vm_name, signatures in self.VM_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in lowered:
                    hits.append(vm_name)
                    break
        return sorted(set(hits))

    def _detect_mobile_ids(self, text: str) -> Dict[str, List[str]]:
        imeis = [m.group(0) for m in self.imei_re.finditer(text)]
        iccids = [m.group(0) for m in self.iccid_re.finditer(text)]
        # IMSI is broader; filter out obvious IMEIs/ICCIDs already captured
        ims_candidates = [m.group(0) for m in self.imsi_re.finditer(text)]
        imsis = [v for v in ims_candidates if v not in imeis and v not in iccids]
        return {
            "imei": sorted(set(imeis)),
            "imsi": sorted(set(imsis)),
            "iccid": sorted(set(iccids)),
        }

    def _detect_burner_patterns(self, text: str) -> Dict[str, Any]:
        indicators: List[str] = []
        for pattern in self.BURNER_HOST_PATTERNS:
            if re.search(pattern, text):
                indicators.append("Generic Windows hostname pattern")
                break

        # Heuristic: repeated default folders can hint at fresh install
        if text.count("\\Users\\") >= 3:
            indicators.append("Multiple default user folder references")

        score = min(1.0, len(indicators) * 0.25)
        return {
            "indicators": indicators,
            "score": score,
            "assessment": self._score_to_label(score),
        }

    def _detect_timezones(self, text: str) -> List[str]:
        hints = [tz for tz in self.TIMEZONE_HINTS if tz in text]
        return sorted(set(hints))

    def _detect_hardware(self, text: str) -> List[str]:
        hints = []
        hardware_markers = ["Intel", "AMD", "Ryzen", "Xeon", "Core i7", "Core i9"]
        for marker in hardware_markers:
            if marker.lower() in text.lower():
                hints.append(marker)
        return sorted(set(hints))

    def _detect_ips(self, text: str) -> List[str]:
        return sorted(set(self.ip_re.findall(text)))

    def _build_recommendations(self, vm_hits: List[str], burner: Dict[str, Any], mobile_ids: Dict[str, List[str]]) -> List[str]:
        recs: List[str] = []
        if vm_hits:
            recs.append("If VM artifacts are present, consider this a staging/test environment.")
        if burner.get("score", 0) >= 0.5:
            recs.append("Burner indicators present; correlate across incidents for pattern reuse.")
        if any(mobile_ids.values()):
            recs.append("Mobile identifiers found; law enforcement can subpoena carrier/retailer.")
        if not recs:
            recs.append("No strong forensic indicators; rely on infrastructure and pattern correlation.")
        return recs

    @staticmethod
    def _score_to_label(score: float) -> str:
        if score >= 0.75:
            return "High"
        if score >= 0.5:
            return "Medium"
        if score >= 0.25:
            return "Low"
        return "Minimal"
