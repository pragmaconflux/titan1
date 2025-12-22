"""Endpoint artifact parsers (cross-platform).

These parsers operate on artifact *files* (exports/triage bundles) and do not
require running on the same OS as the incident.

Scope (minimal addons):
- PowerShell history text (PSReadLine)
- Browser history SQLite (Chrome/Edge History, Firefox places.sqlite)

All parsing is best-effort and dependency-free.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..utils.helpers import extract_iocs
from .evidence_models import EvidenceEvent, Indicator, EvidenceRef


def _chrome_time_to_iso(value: Any) -> Optional[str]:
    """Convert Chrome/WebKit timestamp (microseconds since 1601-01-01) to ISO UTC."""
    if value in (None, ""):
        return None
    try:
        micros = int(value)
    except Exception:
        return None
    if micros <= 0:
        return None
    try:
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        dt = epoch + timedelta(microseconds=micros)
        return dt.isoformat()
    except Exception:
        return None


def _firefox_time_to_iso(value: Any) -> Optional[str]:
    """Convert Firefox visit_date (microseconds since Unix epoch) to ISO UTC."""
    if value in (None, ""):
        return None
    try:
        micros = int(value)
    except Exception:
        return None
    if micros <= 0:
        return None
    try:
        dt = datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def parse_powershell_history(path: Path) -> Tuple[List[EvidenceEvent], List[Indicator]]:
    extracted_by = "endpoint_parser:powershell_history"
    events: List[EvidenceEvent] = []
    indicators: List[Indicator] = []

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return events, indicators

    for idx, line in enumerate(text.splitlines(), start=1):
        cmd = line.strip()
        if not cmd:
            continue

        # PSReadLine history doesn't include timestamps; leave None.
        ev = EvidenceEvent(
            event_type="powershell_command",
            timestamp=None,
            source=str(path),
            extracted_by=extracted_by,
            process="powershell",
            action="command",
            raw={"command": cmd, "_line": idx},
            tags=["endpoint", "powershell"],
        )
        events.append(ev)

        # Extract defensive indicators from the command string.
        try:
            iocs = extract_iocs(cmd)
        except Exception:
            iocs = {}

        ts = None
        for ioc_type, values in (iocs or {}).items():
            if not values:
                continue
            for v in values:
                indicators.append(
                    Indicator(
                        indicator_type=ioc_type,
                        value=str(v),
                        first_seen=ts,
                        last_seen=ts,
                        confidence="medium",
                        tags=["powershell"],
                        sources=[
                            EvidenceRef(
                                evidence_path=str(path),
                                extracted_by=extracted_by,
                                record_id=f"line:{idx}",
                                field="command",
                                preview=cmd[:200],
                            )
                        ],
                    )
                )

    return events, indicators


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,)
    )
    return cur.fetchone() is not None


def parse_browser_history_sqlite(path: Path) -> Tuple[List[EvidenceEvent], List[Indicator]]:
    extracted_by = "endpoint_parser:browser_history"
    events: List[EvidenceEvent] = []
    indicators: List[Indicator] = []

    try:
        conn = sqlite3.connect(str(path))
    except Exception:
        return events, indicators

    try:
        # Chrome/Edge
        if _table_exists(conn, "urls"):
            cur = conn.cursor()
            cols = [
                "url",
                "title",
                "visit_count",
                "last_visit_time",
            ]
            try:
                cur.execute(
                    "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500"
                )
                for row in cur.fetchall():
                    url, title, visit_count, last_visit_time = row
                    ts = _chrome_time_to_iso(last_visit_time)
                    ev = EvidenceEvent(
                        event_type="browser_visit",
                        timestamp=ts,
                        source=str(path),
                        extracted_by=extracted_by,
                        url=str(url) if url else None,
                        outcome=None,
                        raw={
                            "title": title,
                            "visit_count": visit_count,
                            "last_visit_time": last_visit_time,
                        },
                        tags=["endpoint", "browser"],
                    )
                    events.append(ev)

                    if url:
                        indicators.append(
                            Indicator(
                                indicator_type="urls",
                                value=str(url),
                                first_seen=None,
                                last_seen=ts,
                                confidence="high",
                                tags=["browser"],
                                sources=[
                                    EvidenceRef(
                                        evidence_path=str(path),
                                        extracted_by=extracted_by,
                                        record_id=None,
                                        field="urls.url",
                                        preview=str(url)[:200],
                                    )
                                ],
                            )
                        )
            except Exception:
                pass

        # Firefox places.sqlite
        if _table_exists(conn, "moz_places"):
            cur = conn.cursor()
            # visit_date in moz_historyvisits is microseconds since epoch
            try:
                cur.execute(
                    "SELECT p.url, hv.visit_date FROM moz_places p JOIN moz_historyvisits hv ON p.id = hv.place_id ORDER BY hv.visit_date DESC LIMIT 500"
                )
                for url, visit_date in cur.fetchall():
                    ts = _firefox_time_to_iso(visit_date)
                    ev = EvidenceEvent(
                        event_type="browser_visit",
                        timestamp=ts,
                        source=str(path),
                        extracted_by=extracted_by,
                        url=str(url) if url else None,
                        raw={"visit_date": visit_date},
                        tags=["endpoint", "browser"],
                    )
                    events.append(ev)
                    if url:
                        indicators.append(
                            Indicator(
                                indicator_type="urls",
                                value=str(url),
                                first_seen=None,
                                last_seen=ts,
                                confidence="high",
                                tags=["browser"],
                                sources=[
                                    EvidenceRef(
                                        evidence_path=str(path),
                                        extracted_by=extracted_by,
                                        record_id=None,
                                        field="moz_places.url",
                                        preview=str(url)[:200],
                                    )
                                ],
                            )
                        )
            except Exception:
                pass

    finally:
        try:
            conn.close()
        except Exception:
            pass

    return events, indicators
