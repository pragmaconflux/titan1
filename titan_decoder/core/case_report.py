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


def build_case_report(
    report: Dict[str, Any], forensics: Dict[str, Any] | None, iocs: Dict[str, Any]
) -> Dict[str, Any]:
    evidence = report.get("evidence") or {}
    return {
        "meta": report.get("meta", {}),
        "node_count": report.get("node_count", 0),
        "iocs": iocs,
        "forensics": forensics or {},
        "evidence": {
            "event_count": len(evidence.get("events") or []),
            "indicator_count": len(evidence.get("indicators") or []),
            "top_pivots": evidence.get("top_pivots") or [],
            "top_links": evidence.get("top_links") or [],
            "entity_hints": evidence.get("entity_hints") or {},
            "last_seen": evidence.get("last_seen") or {},
        }
        if evidence
        else {},
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

    ev = case.get("evidence") or {}
    if ev:
        lines.append("## Evidence (Normalized)")
        lines.append(f"- event_count: {ev.get('event_count', 0)}")
        lines.append(f"- indicator_count: {ev.get('indicator_count', 0)}")
        pivots = ev.get("top_pivots") or []
        if pivots:
            lines.append("")
            lines.append("### Top Pivots")
            for p in pivots[:10]:
                lines.append(
                    f"- {p.get('type')}={p.get('value')} (sources={p.get('source_count')}, last_seen={p.get('last_seen')}, confidence={p.get('confidence')})"
                )
        entities = ev.get("entity_hints") or {}
        if entities:
            lines.append("")
            lines.append("### Entity Hints")
            lines.append(json.dumps(entities, indent=2))

        links = ev.get("top_links") or []
        if links:
            lines.append("")
            lines.append("### Top Links")
            for l in links[:10]:
                src = (l.get("src") or {})
                dst = (l.get("dst") or {})
                lines.append(
                    f"- {src.get('type')}={src.get('value')} -> {dst.get('type')}={dst.get('value')} ({l.get('reason_code')}, confidence={l.get('confidence')})"
                )
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


def to_html(case: Dict[str, Any]) -> str:
    meta = case.get("meta", {})
    iocs = case.get("iocs", {})
    forensics = case.get("forensics", {}) or {}
    recs = case.get("recommendations", [])
    ev = case.get("evidence") or {}

    def esc(s: str) -> str:
        return (
            str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    ioc_rows = []
    for key, values in iocs.items():
        if not values:
            ioc_rows.append(f"<tr><td>{esc(key)}</td><td><em>None</em></td></tr>")
        else:
            ioc_rows.append(
                f"<tr><td>{esc(key)}</td><td><code>{esc(', '.join(values))}</code></td></tr>"
            )

    rec_items = "".join(f"<li>{esc(r)}</li>" for r in recs) or "<li>None</li>"

    pivots = ev.get("top_pivots") or []
    pivot_rows = []
    for p in pivots[:10]:
        pivot_rows.append(
            "<tr>"
            f"<td>{esc(p.get('type'))}</td>"
            f"<td><code>{esc(p.get('value'))}</code></td>"
            f"<td>{esc(p.get('confidence'))}</td>"
            f"<td>{esc(p.get('source_count'))}</td>"
            f"<td>{esc(p.get('last_seen'))}</td>"
            "</tr>"
        )

    return "\n".join(
        [
            "<!doctype html>",
            "<html lang='en'>",
            "<head>",
            "  <meta charset='utf-8'>",
            "  <meta name='viewport' content='width=device-width, initial-scale=1'>",
            "  <title>Titan Case Report</title>",
            "  <style>",
            "    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }",
            "    code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }",
            "    pre { background: #f6f8fa; padding: 1rem; overflow-x: auto; }",
            "    table { border-collapse: collapse; width: 100%; }",
            "    th, td { border: 1px solid #ddd; padding: 0.5rem; vertical-align: top; }",
            "    th { background: #f2f2f2; text-align: left; }",
            "  </style>",
            "</head>",
            "<body>",
            "  <h1>Titan Case Report</h1>",
            "  <h2>Meta</h2>",
            f"  <pre>{esc(json.dumps(meta, indent=2))}</pre>",
            "  <h2>Indicators</h2>",
            "  <table>",
            "    <thead><tr><th>Type</th><th>Values</th></tr></thead>",
            "    <tbody>",
            *["    " + row for row in ioc_rows],
            "    </tbody>",
            "  </table>",
            "  <h2>Forensics</h2>",
            f"  <pre>{esc(json.dumps(forensics, indent=2))}</pre>",
            "  <h2>Evidence (Normalized)</h2>",
            f"  <pre>{esc(json.dumps(ev, indent=2))}</pre>"
            if ev and not pivot_rows
            else "  <p><em>No evidence ingested.</em></p>"
            if not ev
            else "  <table><thead><tr><th>Type</th><th>Value</th><th>Confidence</th><th>Sources</th><th>Last Seen</th></tr></thead><tbody>"
            + "".join(pivot_rows)
            + "</tbody></table>",
            "  <h2>Recommendations</h2>",
            f"  <ul>{rec_items}</ul>",
            "</body>",
            "</html>",
        ]
    )


def _recommendations(
    forensics: Dict[str, Any] | None, iocs: Dict[str, Any]
) -> List[str]:
    recs: List[str] = []
    if not forensics:
        recs.append("Review IOCs; consider correlation with prior incidents.")
        return recs

    vm = (forensics or {}).get("vm", {})
    if vm.get("detected"):
        recs.append(
            "VM artifacts present—consider staging/test environment attribution."
        )

    burner = (forensics or {}).get("burner", {})
    if burner.get("score", 0) >= 0.5:
        recs.append(
            "Burner indicators present—correlate across incidents for reuse patterns."
        )

    mobile = (forensics or {}).get("mobile_ids", {})
    if any(mobile.values()):
        recs.append("Mobile IDs found—law enforcement can subpoena carrier/retailer.")

    tz = (forensics or {}).get("timezone_hints", [])
    if tz:
        recs.append(f"Timezone hints found: {', '.join(tz)}")

    if not recs:
        recs.append(
            "No strong forensic indicators—focus on infrastructure and IOC correlation."
        )
    return recs
