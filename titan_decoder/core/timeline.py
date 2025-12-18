"""Timeline builder for Titan analysis runs.

Produces a lightweight sequence of events from the analysis report. This is
intended for quick triage, CSV export, or ingestion into external tools.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List


def build_timeline(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Create an ordered event list from an analysis report."""
    nodes = report.get("nodes", [])
    timeline: List[Dict[str, Any]] = []
    for order, node in enumerate(nodes):
        timeline.append({
            "order": order,
            "id": node.get("id"),
            "parent": node.get("parent"),
            "depth": node.get("depth"),
            "method": node.get("method"),
            "decoder": node.get("decoder_used"),
            "content_type": node.get("content_type"),
            "size": node.get("decoded_length") or node.get("source_length"),
            "sha256": node.get("sha256"),
            "score": node.get("decode_score"),
            "pruned": node.get("pruned", False),
            "preview": (node.get("content_preview") or "")[:160],
        })
    return timeline


def export_timeline(timeline: List[Dict[str, Any]], path: Path, fmt: str = "json") -> None:
    """Export a timeline to disk."""
    fmt = fmt.lower()
    if fmt == "json":
        path.write_text(json.dumps(timeline, indent=2))
        return
    if fmt == "csv":
        fieldnames = [
            "order",
            "id",
            "parent",
            "depth",
            "method",
            "decoder",
            "content_type",
            "size",
            "sha256",
            "score",
            "pruned",
            "preview",
        ]
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(timeline)
        return
    raise ValueError(f"Unsupported timeline format: {fmt}")
