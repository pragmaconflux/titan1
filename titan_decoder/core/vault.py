"""Local vault for storing runs and searching prior analyses.

Goal: provide enterprise-like "case context" for budget users, without needing
an external platform.

This stores:
- run metadata (analysis_id, report_path, timestamps)
- indicators (type/value)
- links between runs and indicators
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    analysis_id TEXT PRIMARY KEY,
    report_path TEXT NOT NULL,
    created_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    node_count INTEGER,
    risk_level TEXT,
    risk_score INTEGER,
    ioc_count INTEGER
);
CREATE TABLE IF NOT EXISTS indicators (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(type, value)
);
CREATE TABLE IF NOT EXISTS run_indicators (
    analysis_id TEXT NOT NULL,
    indicator_id INTEGER NOT NULL,
    FOREIGN KEY(analysis_id) REFERENCES runs(analysis_id),
    FOREIGN KEY(indicator_id) REFERENCES indicators(id)
);
CREATE INDEX IF NOT EXISTS idx_ind_type_value ON indicators(type, value);
CREATE INDEX IF NOT EXISTS idx_run_ind_analysis ON run_indicators(analysis_id);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_ts);
"""


class VaultStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def __enter__(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.executescript(SCHEMA)
        self._migrate_schema()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.conn:
            self.conn.commit()
            self.conn.close()

    def _migrate_schema(self) -> None:
        """Best-effort schema migrations for older vault DBs."""
        cur = self.conn.cursor()
        cur.execute("PRAGMA table_info(runs)")
        cols = {row[1] for row in cur.fetchall()}

        # Add summary columns if missing.
        if "node_count" not in cols:
            cur.execute("ALTER TABLE runs ADD COLUMN node_count INTEGER")
        if "risk_level" not in cols:
            cur.execute("ALTER TABLE runs ADD COLUMN risk_level TEXT")
        if "risk_score" not in cols:
            cur.execute("ALTER TABLE runs ADD COLUMN risk_score INTEGER")
        if "ioc_count" not in cols:
            cur.execute("ALTER TABLE runs ADD COLUMN ioc_count INTEGER")

        self.conn.commit()

    def record_run(
        self,
        analysis_id: str,
        report_path: Path,
        node_count: Optional[int] = None,
        risk_level: Optional[str] = None,
        risk_score: Optional[int] = None,
        ioc_count: Optional[int] = None,
    ) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            INSERT OR REPLACE INTO runs(
                analysis_id, report_path, node_count, risk_level, risk_score, ioc_count
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                analysis_id,
                str(report_path),
                node_count,
                risk_level,
                risk_score,
                ioc_count,
            ),
        )
        self.conn.commit()

    def record_iocs(self, analysis_id: str, iocs: Dict[str, Any]) -> None:
        cur = self.conn.cursor()
        for t, values in (iocs or {}).items():
            if not values:
                continue
            for v in values:
                cur.execute(
                    "INSERT OR IGNORE INTO indicators(type, value) VALUES (?, ?)",
                    (str(t), str(v)),
                )
                cur.execute(
                    "SELECT id FROM indicators WHERE type=? AND value=?", (str(t), str(v))
                )
                row = cur.fetchone()
                if not row:
                    continue
                ind_id = row[0]
                # Avoid duplicate links without requiring a unique constraint.
                cur.execute(
                    "SELECT 1 FROM run_indicators WHERE analysis_id=? AND indicator_id=?",
                    (analysis_id, ind_id),
                )
                if cur.fetchone() is None:
                    cur.execute(
                        "INSERT INTO run_indicators(analysis_id, indicator_id) VALUES (?, ?)",
                        (analysis_id, ind_id),
                    )
        self.conn.commit()

    def search_value(self, value: str, ioc_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search prior runs for an exact indicator value (optionally filtered by type)."""
        cur = self.conn.cursor()
        if ioc_type:
            cur.execute(
                """
                SELECT i.type, i.value, r.analysis_id, r.report_path, r.created_ts,
                       r.node_count, r.risk_level, r.risk_score, r.ioc_count
                FROM indicators i
                JOIN run_indicators ri ON ri.indicator_id = i.id
                JOIN runs r ON r.analysis_id = ri.analysis_id
                WHERE i.value = ? AND i.type = ?
                ORDER BY r.created_ts DESC
                """,
                (value, str(ioc_type)),
            )
        else:
            cur.execute(
                """
                SELECT i.type, i.value, r.analysis_id, r.report_path, r.created_ts,
                       r.node_count, r.risk_level, r.risk_score, r.ioc_count
                FROM indicators i
                JOIN run_indicators ri ON ri.indicator_id = i.id
                JOIN runs r ON r.analysis_id = ri.analysis_id
                WHERE i.value = ?
                ORDER BY r.created_ts DESC
                """,
                (value,),
            )
        rows = cur.fetchall()
        return [
            {
                "type": r[0],
                "value": r[1],
                "analysis_id": r[2],
                "report_path": r[3],
                "created_ts": r[4],
                "node_count": r[5],
                "risk_level": r[6],
                "risk_score": r[7],
                "ioc_count": r[8],
            }
            for r in rows
        ]

    def list_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute(
            """
            SELECT analysis_id, report_path, created_ts, node_count, risk_level, risk_score, ioc_count
            FROM runs
            ORDER BY created_ts DESC
            LIMIT ?
            """,
            (int(limit),),
        )
        rows = cur.fetchall()
        return [
            {
                "analysis_id": r[0],
                "report_path": r[1],
                "created_ts": r[2],
                "node_count": r[3],
                "risk_level": r[4],
                "risk_score": r[5],
                "ioc_count": r[6],
            }
            for r in rows
        ]

    def prune_days(self, days: int) -> Dict[str, Any]:
        """Delete runs older than N days and garbage-collect unreferenced indicators."""
        days = int(days)
        cur = self.conn.cursor()

        # Count before.
        cur.execute("SELECT COUNT(*) FROM runs")
        before_runs = int(cur.fetchone()[0])

        cur.execute(
            "DELETE FROM runs WHERE created_ts < datetime('now', ?) ",
            (f"-{days} days",),
        )
        deleted_runs = cur.rowcount

        # Remove dangling run_indicators rows.
        cur.execute(
            "DELETE FROM run_indicators WHERE analysis_id NOT IN (SELECT analysis_id FROM runs)"
        )

        # Remove indicators no longer referenced.
        cur.execute(
            "DELETE FROM indicators WHERE id NOT IN (SELECT DISTINCT indicator_id FROM run_indicators)"
        )

        self.conn.commit()

        cur.execute("SELECT COUNT(*) FROM runs")
        after_runs = int(cur.fetchone()[0])
        return {
            "before_runs": before_runs,
            "after_runs": after_runs,
            "deleted_runs": int(deleted_runs),
        }
