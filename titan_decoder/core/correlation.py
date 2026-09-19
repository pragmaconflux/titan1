"""Simple SQLite-based correlation cache for IOCs.

Deprecated: superseded by the Phase 5 correlation package
(``titan_decoder.correlation``), which persists full indicator records with
evidence references and supports relationship scoring, campaign clustering,
and cross-case search (``--correlation-db`` / ``--correlation-search``).
This store remains only for existing ``enable_correlation`` configs.

Stores seen indicators and links new analyses to prior ones. Optional and
lightweight—if disabled or DB unavailable, it safely no-ops.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(type, value)
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
        self.conn: Optional[sqlite3.Connection] = None

    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path)
        self.conn.executescript(SCHEMA)
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.conn:
            self.conn.commit()
            self.conn.close()

    @property
    def _db(self) -> sqlite3.Connection:
        """Return the open connection, narrowed.

        The query methods are only valid inside
        ``with CorrelationStore(path) as store``; using the store outside its
        context otherwise failed with an AttributeError on None instead of
        saying so.
        """
        if self.conn is None:
            raise RuntimeError(
                "correlation store is not open; "
                "use 'with CorrelationStore(path) as store:'"
            )
        return self.conn

    def record_analysis(self, analysis_id: str, iocs: Dict[str, Any]):
        # Note: INSERT OR IGNORE relies on the UNIQUE(type, value) constraint;
        # without it (as in pre-fix databases) every run re-inserted duplicate
        # indicator rows.
        cur = self._db.cursor()
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
                # Avoid duplicate links for the same run.
                cur.execute(
                    "SELECT 1 FROM analysis_links WHERE analysis_id=? AND indicator_id=?",
                    (analysis_id, ind_id),
                )
                if cur.fetchone() is None:
                    cur.execute(
                        "INSERT INTO analysis_links(analysis_id, indicator_id) VALUES (?, ?)",
                        (analysis_id, ind_id),
                    )
        self._db.commit()

    def correlate(self, iocs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return list of matches with prior analyses."""
        cur = self._db.cursor()
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
