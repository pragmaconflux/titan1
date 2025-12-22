"""Evidence timeline export.

Exports the normalized `report.evidence.events` timeline (not the node timeline).
This is useful for IR handoffs and timeline tooling.

Dependency-free.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List


def build_evidence_timeline(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    evidence = report.get("evidence") or {}
    events = evidence.get("events") or []

    # Sort by timestamp, then event_type, then source.
    def key(ev: Dict[str, Any]) -> tuple:
        return (
            ev.get("timestamp") or "",
            ev.get("event_type") or "",
            ev.get("source") or "",
            ev.get("event_id") or "",
        )

    out = sorted(events, key=key)
    return out


def export_evidence_timeline(timeline: List[Dict[str, Any]], path: Path, fmt: str = "json") -> None:
    fmt = (fmt or "json").lower()
    if fmt == "json":
        path.write_text(json.dumps(timeline, indent=2))
        return
    if fmt == "csv":
        fieldnames = [
            "timestamp",
            "event_type",
            "host",
            "user",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "proto",
            "domain",
            "url",
            "process",
            "file_path",
            "sha256",
            "action",
            "outcome",
            "source",
            "extracted_by",
        ]
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for ev in timeline:
                writer.writerow({k: ev.get(k) for k in fieldnames})
        return
    raise ValueError(f"Unsupported evidence timeline format: {fmt}")
