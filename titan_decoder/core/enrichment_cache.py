"""Deterministic enrichment cache (SQLite).

Enterprise-grade enrichment needs:
- repeatable results (cache by default)
- provenance (when/how cached)
- explicit refresh control

This module is dependency-free.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


SCHEMA = """
CREATE TABLE IF NOT EXISTS enrichment_cache (
  provider TEXT NOT NULL,
  indicator_type TEXT NOT NULL,
  indicator_value TEXT NOT NULL,
  cached_at TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY (provider, indicator_type, indicator_value)
);
"""


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class CacheHit:
    provider: str
    indicator_type: str
    indicator_value: str
    cached_at: str
    payload: Dict[str, Any]


class EnrichmentCache:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        return conn

    def get(self, provider: str, indicator_type: str, indicator_value: str) -> Optional[CacheHit]:
        provider = (provider or "").strip().lower()
        indicator_type = (indicator_type or "").strip().lower()
        indicator_value = (indicator_value or "").strip()
        if not provider or not indicator_type or not indicator_value:
            return None

        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT cached_at, payload_json FROM enrichment_cache WHERE provider=? AND indicator_type=? AND indicator_value=?",
                (provider, indicator_type, indicator_value),
            )
            row = cur.fetchone()
            if not row:
                return None
            cached_at, payload_json = row
            try:
                payload = json.loads(payload_json)
            except Exception:
                payload = {}
            return CacheHit(
                provider=provider,
                indicator_type=indicator_type,
                indicator_value=indicator_value,
                cached_at=str(cached_at),
                payload=payload,
            )
        finally:
            conn.close()

    def set(self, provider: str, indicator_type: str, indicator_value: str, payload: Dict[str, Any]) -> str:
        provider = (provider or "").strip().lower()
        indicator_type = (indicator_type or "").strip().lower()
        indicator_value = (indicator_value or "").strip()
        if not provider or not indicator_type or not indicator_value:
            return _utc_now_iso()

        cached_at = _utc_now_iso()
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO enrichment_cache(provider, indicator_type, indicator_value, cached_at, payload_json) VALUES (?, ?, ?, ?, ?)",
                (provider, indicator_type, indicator_value, cached_at, json.dumps(payload, sort_keys=True)),
            )
            conn.commit()
        finally:
            conn.close()
        return cached_at

    def stats(self) -> Dict[str, Any]:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM enrichment_cache")
            (count,) = cur.fetchone() or (0,)
            return {"entries": int(count)}
        finally:
            conn.close()
