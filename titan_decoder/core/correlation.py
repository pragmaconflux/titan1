"""Simple SQLite-based correlation cache for IOCs.

Stores seen indicators and links new analyses to prior ones. Optional and
lightweight—if disabled or DB unavailable, it safely no-ops.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, Any, List

SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen_ts DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS analysis_links (
    analysis_id TEXT,
    indicator_id INTEGER,
    FOREIGN KEY(indicator_id) REFERENCES indicators(id)
);
CREATE INDEX IF NOT EXISTS idx_ind_type_value ON indicators(type, value);
"""


class CorrelationStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = None

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.executescript(SCHEMA)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.conn:
            self.conn.commit()
            self.conn.close()

    def record_analysis(self, analysis_id: str, iocs: Dict[str, Any]):
        cur = self.conn.cursor()
        for t, values in iocs.items():
            for v in values:
                cur.execute(
                    "INSERT OR IGNORE INTO indicators(type, value) VALUES (?, ?)",
                    (t, v),
                )
                cur.execute(
                    "SELECT id FROM indicators WHERE type=? AND value=?", (t, v)
                )
                row = cur.fetchone()
                if not row:
                    continue
                ind_id = row[0]
                cur.execute(
                    "INSERT INTO analysis_links(analysis_id, indicator_id) VALUES (?, ?)",
                    (analysis_id, ind_id),
                )
        self.conn.commit()

    def correlate(self, iocs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return list of matches with prior analyses."""
        cur = self.conn.cursor()
        matches = []
        for t, values in iocs.items():
            for v in values:
                cur.execute(
                    "SELECT analysis_id FROM analysis_links al JOIN indicators i ON al.indicator_id=i.id WHERE i.type=? AND i.value=?",
                    (t, v),
                )
                for row in cur.fetchall():
                    matches.append({"type": t, "value": v, "analysis_id": row[0]})
        return matches
