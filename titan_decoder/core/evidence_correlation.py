"""Evidence correlation and pivots.

Takes normalized EvidenceEvent + Indicator data and produces:
- last seen summaries per indicator
- top pivots (most frequent / most recent / multi-source)

This is intentionally lightweight and deterministic.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .evidence_models import Indicator


def build_last_seen(indicators: List[Indicator]) -> Dict[str, Dict[str, Any]]:
    """Return a mapping of `type:value` -> summary."""
    out: Dict[str, Dict[str, Any]] = {}
    for ind in indicators:
        t = ind.indicator_type
        v = ind.value
        key = f"{t}:{v}"
        sources = len(ind.sources)
        out[key] = {
            "type": t,
            "value": v,
            "first_seen": ind.first_seen,
            "last_seen": ind.last_seen,
            "confidence": ind.confidence,
            "source_count": sources,
            "tags": ind.tags,
        }
    return out


def top_pivots(indicators: List[Indicator], limit: int = 10) -> List[Dict[str, Any]]:
    """Return top pivots ordered by (source_count, recency, type/value)."""
    scored: List[Tuple[Tuple[int, str, str, str], Indicator]] = []
    for ind in indicators:
        # Recency: ISO strings sort lexicographically for UTC timestamps.
        recency = ind.last_seen or ""
        score_key = (
            len(ind.sources),
            recency,
            ind.indicator_type,
            ind.value,
        )
        scored.append((score_key, ind))

    scored.sort(key=lambda x: x[0], reverse=True)

    pivots: List[Dict[str, Any]] = []
    for _, ind in scored[: max(0, int(limit))]:
        pivots.append(
            {
                "type": ind.indicator_type,
                "value": ind.value,
                "first_seen": ind.first_seen,
                "last_seen": ind.last_seen,
                "confidence": ind.confidence,
                "source_count": len(ind.sources),
                "tags": ind.tags,
                "sources": [s.to_dict() for s in ind.sources[:5]],
            }
        )
    return pivots


def build_entity_hints(indicators: List[Indicator]) -> Dict[str, Any]:
    """Very lightweight entity grouping for report readability."""
    by_type: Dict[str, List[Indicator]] = defaultdict(list)
    for ind in indicators:
        by_type[ind.indicator_type].append(ind)

    def uniq_vals(t: str, max_n: int = 50) -> List[str]:
        vals = sorted({i.value for i in by_type.get(t, [])})
        return vals[:max_n]

    return {
        "infrastructure": {
            "domains": uniq_vals("domains"),
            "urls": uniq_vals("urls"),
            "ips": uniq_vals("ipv4")[:50],
        },
        "identity": {
            "users": uniq_vals("users"),
        },
        "assets": {
            "hosts": uniq_vals("hostnames"),
            "mac_addresses": uniq_vals("mac_addresses"),
        },
        "client_fingerprints": {
            "user_agents": uniq_vals("user_agents"),
        },
    }
