"""Case report generator for investigators / law enforcement.

Produces a structured dict and optional Markdown summary combining:
- Executive summary
- Indicators (IOCs)
- Forensic hints (VM/burner/mobile/timezone)
- Infrastructure (basic IP/domain lists; enrichment can be plugged later)
- Recommendations
"""

from __future__ import annotations

import json
from typing import Dict, Any, List


def build_case_report(report: Dict[str, Any], forensics: Dict[str, Any] | None, iocs: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "meta": report.get("meta", {}),
        "node_count": report.get("node_count", 0),
        "iocs": iocs,
        "forensics": forensics or {},
        "recommendations": _recommendations(forensics, iocs),
    }


def to_markdown(case: Dict[str, Any]) -> str:
    lines: List[str] = []
    meta = case.get("meta", {})
    lines.append("# Titan Case Report")
    lines.append("")
    if meta:
        lines.append("## Meta")
        lines.append(json.dumps(meta, indent=2))
        lines.append("")

    lines.append("## Indicators")
    iocs = case.get("iocs", {})
    for key, values in iocs.items():
        lines.append(f"- {key}: {', '.join(values) if values else 'None'}")
    lines.append("")

    lines.append("## Forensics")
    f = case.get("forensics", {}) or {}
    lines.append(json.dumps(f, indent=2))
    lines.append("")

    lines.append("## Recommendations")
    for rec in case.get("recommendations", []):
        lines.append(f"- {rec}")
    lines.append("")
    return "\n".join(lines)


def _recommendations(forensics: Dict[str, Any] | None, iocs: Dict[str, Any]) -> List[str]:
    recs: List[str] = []
    if not forensics:
        recs.append("Review IOCs; consider correlation with prior incidents.")
        return recs

    vm = (forensics or {}).get("vm", {})
    if vm.get("detected"):
        recs.append("VM artifacts present—consider staging/test environment attribution.")

    burner = (forensics or {}).get("burner", {})
    if burner.get("score", 0) >= 0.5:
        recs.append("Burner indicators present—correlate across incidents for reuse patterns.")

    mobile = (forensics or {}).get("mobile_ids", {})
    if any(mobile.values()):
        recs.append("Mobile IDs found—law enforcement can subpoena carrier/retailer.")

    tz = (forensics or {}).get("timezone_hints", [])
    if tz:
        recs.append(f"Timezone hints found: {', '.join(tz)}")

    if not recs:
        recs.append("No strong forensic indicators—focus on infrastructure and IOC correlation.")
    return recs
