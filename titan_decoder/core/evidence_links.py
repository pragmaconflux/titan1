"""Build a lightweight evidence correlation graph.

This produces explicit link objects (edges) between entities/observables with:
- reason codes (deterministic, machine comparable)
- confidence labels
- evidence references (provenance)

Goal: "pivots with proof" without heavy dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class EvidenceLink:
    src_type: str
    src_value: str
    dst_type: str
    dst_value: str
    reason_code: str
    confidence: str = "medium"  # low/medium/high
    sources: List[Dict[str, Any]] = field(default_factory=list)

    def key(self) -> tuple[str, str, str, str, str]:
        return (self.src_type, self.src_value, self.dst_type, self.dst_value, self.reason_code)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src": {"type": self.src_type, "value": self.src_value},
            "dst": {"type": self.dst_type, "value": self.dst_value},
            "reason_code": self.reason_code,
            "confidence": self.confidence,
            "sources": self.sources,
        }


def _coerce_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _add_link(links: Dict[tuple, EvidenceLink], link: EvidenceLink) -> None:
    k = link.key()
    if k not in links:
        links[k] = link
        return
    # Merge sources; keep highest confidence.
    existing = links[k]
    merged_sources = list(existing.sources)
    seen = {json_key(s) for s in merged_sources}
    for s in link.sources:
        if json_key(s) in seen:
            continue
        merged_sources.append(s)
        seen.add(json_key(s))

    conf_order = {"low": 0, "medium": 1, "high": 2}
    best_conf = existing.confidence
    if conf_order.get(link.confidence, 1) > conf_order.get(best_conf, 1):
        best_conf = link.confidence

    links[k] = EvidenceLink(
        src_type=existing.src_type,
        src_value=existing.src_value,
        dst_type=existing.dst_type,
        dst_value=existing.dst_value,
        reason_code=existing.reason_code,
        confidence=best_conf,
        sources=merged_sources,
    )


def json_key(source: Dict[str, Any]) -> str:
    # Stable key for best-effort de-dupe
    return "|".join(
        str(source.get(k) or "")
        for k in ("evidence_path", "extracted_by", "record_id", "field")
    )


def build_links_from_evidence_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Derive evidence links from normalized evidence events.

    Expects event dicts as produced by EvidenceEvent.to_dict().
    """
    links: Dict[tuple, EvidenceLink] = {}

    for ev in events:
        src = _coerce_str(ev.get("src_ip"))
        dst = _coerce_str(ev.get("dst_ip"))
        domain = _coerce_str(ev.get("domain"))
        url = _coerce_str(ev.get("url"))
        user = _coerce_str(ev.get("user"))
        host = _coerce_str(ev.get("host"))
        ua = _coerce_str(ev.get("raw", {}).get("user_agent")) or _coerce_str(
            ev.get("raw", {}).get("ua")
        )
        event_type = _coerce_str(ev.get("event_type")) or ""

        # Provenance ref: take minimal fields available
        src_ref = {
            "evidence_path": ev.get("source"),
            "extracted_by": ev.get("extracted_by"),
            "record_id": None,
            "field": None,
        }

        # DNS: domain -> answer IP
        if event_type == "dns_query" and domain and dst:
            _add_link(
                links,
                EvidenceLink(
                    src_type="domains",
                    src_value=domain,
                    dst_type="ipv4",
                    dst_value=dst,
                    reason_code="dns_resolves_to_ip",
                    confidence="high",
                    sources=[src_ref],
                ),
            )

        # Proxy: url -> domain (if both present)
        if event_type == "proxy_request" and url and domain:
            _add_link(
                links,
                EvidenceLink(
                    src_type="urls",
                    src_value=url,
                    dst_type="domains",
                    dst_value=domain,
                    reason_code="proxy_url_host",
                    confidence="high",
                    sources=[src_ref],
                ),
            )

        # Proxy: user -> url
        if event_type == "proxy_request" and user and url:
            _add_link(
                links,
                EvidenceLink(
                    src_type="users",
                    src_value=user,
                    dst_type="urls",
                    dst_value=url,
                    reason_code="proxy_user_requested_url",
                    confidence="medium",
                    sources=[src_ref],
                ),
            )

        # Proxy: host -> url
        if event_type == "proxy_request" and host and url:
            _add_link(
                links,
                EvidenceLink(
                    src_type="hostnames",
                    src_value=host,
                    dst_type="urls",
                    dst_value=url,
                    reason_code="proxy_host_requested_url",
                    confidence="medium",
                    sources=[src_ref],
                ),
            )

        # Proxy: user-agent -> url
        if event_type == "proxy_request" and ua and url:
            _add_link(
                links,
                EvidenceLink(
                    src_type="user_agents",
                    src_value=ua,
                    dst_type="urls",
                    dst_value=url,
                    reason_code="proxy_user_agent_requested_url",
                    confidence="low",
                    sources=[src_ref],
                ),
            )

        # Firewall flow: src_ip -> dst_ip
        if event_type == "network_flow" and src and dst:
            _add_link(
                links,
                EvidenceLink(
                    src_type="ipv4",
                    src_value=src,
                    dst_type="ipv4",
                    dst_value=dst,
                    reason_code="firewall_flow",
                    confidence="medium",
                    sources=[src_ref],
                ),
            )

        # Auth: user -> src_ip
        if event_type == "auth_event" and user and src:
            _add_link(
                links,
                EvidenceLink(
                    src_type="users",
                    src_value=user,
                    dst_type="ipv4",
                    dst_value=src,
                    reason_code="auth_user_source_ip",
                    confidence="medium",
                    sources=[src_ref],
                ),
            )

        # VPN: user -> src_ip
        if event_type == "vpn_session" and user and src:
            _add_link(
                links,
                EvidenceLink(
                    src_type="users",
                    src_value=user,
                    dst_type="ipv4",
                    dst_value=src,
                    reason_code="vpn_user_source_ip",
                    confidence="high",
                    sources=[src_ref],
                ),
            )

    # Return deterministic ordering
    out = [l.to_dict() for l in sorted(links.values(), key=lambda x: (x.src_type, x.src_value, x.dst_type, x.dst_value, x.reason_code))]
    return out


def top_links(links: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    """Rank links by number of sources then lexicographically."""
    def score(l: Dict[str, Any]) -> tuple[int, str, str, str, str, str]:
        src = l.get("src") or {}
        dst = l.get("dst") or {}
        return (
            len(l.get("sources") or []),
            str(l.get("confidence") or ""),
            str(l.get("reason_code") or ""),
            str(src.get("type") or ""),
            str(src.get("value") or ""),
            str(dst.get("value") or ""),
        )

    ranked = sorted(links, key=score, reverse=True)
    return ranked[: max(0, int(limit))]
