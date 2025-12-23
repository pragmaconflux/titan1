"""IR evidence parsers.

Parses common DFIR log/artifact exports and emits canonical EvidenceEvent and
Indicator objects.

Scope (minimal-addons, high-ROI):
- JSONL and CSV inputs (common export formats)
- DNS / Proxy / Firewall / VPN / Auth / DHCP as "kinds"
- Best-effort field mapping; unknown fields preserved in event.raw

This module is intentionally dependency-free.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

from .evidence_models import (
    EvidenceEvent,
    EvidenceRef,
    Indicator,
    merge_indicators,
    normalize_indicator_type,
    parse_timestamp,
)
from .endpoint_parsers import parse_powershell_history, parse_browser_history_sqlite


@dataclass(frozen=True)
class ParseResult:
    events: List[EvidenceEvent]
    indicators: List[Indicator]


def _read_jsonl(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                # Skip invalid line; never crash the entire run.
                continue
            if isinstance(obj, dict):
                obj.setdefault("_line", line_no)
                yield obj


def _read_csv(path: Path) -> Iterator[Dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        for row_no, row in enumerate(reader, start=2):
            # row_no=2 because header is line 1
            row = dict(row)
            row.setdefault("_line", row_no)
            yield row


def _detect_format(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    if suffix in {".csv"}:
        return "csv"

    # Best-effort sniff: if first non-empty line is JSON, treat as jsonl
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                s = line.strip()
                if not s:
                    continue
                if s.startswith("{") and s.endswith("}"):
                    return "jsonl"
                return "csv"  # default fallback
    except Exception:
        return "csv"


def load_records(path: Path) -> List[Dict[str, Any]]:
    fmt = _detect_format(path)
    if fmt == "jsonl":
        return list(_read_jsonl(path))
    return list(_read_csv(path))


def _as_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        try:
            return int(float(v))
        except Exception:
            return None
    if isinstance(value, float):
        return int(value)
    return None


def _pick(record: Dict[str, Any], keys: Iterable[str]) -> Optional[Any]:
    for k in keys:
        if k in record and record.get(k) not in (None, ""):
            return record.get(k)
    return None


def _mk_ref(path: Path, extracted_by: str, record: Dict[str, Any], field: str | None = None) -> EvidenceRef:
    rid = None
    if "_line" in record:
        rid = f"line:{record.get('_line')}"
    elif "id" in record:
        rid = str(record.get("id"))
    preview = None
    try:
        preview = json.dumps({k: record.get(k) for k in list(record.keys())[:12]}, ensure_ascii=False)[:500]
    except Exception:
        preview = None
    return EvidenceRef(
        evidence_path=str(path),
        extracted_by=extracted_by,
        record_id=rid,
        field=field,
        preview=preview,
    )


def _extract_indicators_from_fields(
    path: Path,
    extracted_by: str,
    record: Dict[str, Any],
    ts: Optional[str],
    field_map: List[Tuple[str, str]],
    confidence: str = "medium",
    tags: Optional[List[str]] = None,
) -> List[Indicator]:
    inds: List[Indicator] = []
    tags = tags or []
    for field, ind_type in field_map:
        val = record.get(field)
        if val in (None, ""):
            continue
        # Split on common separators for multi-values
        values: List[str]
        if isinstance(val, str) and "," in val:
            values = [v.strip() for v in val.split(",") if v.strip()]
        elif isinstance(val, list):
            values = [str(v).strip() for v in val if str(v).strip()]
        else:
            values = [str(val).strip()]

        for v in values:
            inds.append(
                Indicator(
                    indicator_type=normalize_indicator_type(ind_type),
                    value=v,
                    first_seen=ts,
                    last_seen=ts,
                    confidence=confidence,
                    tags=list(tags),
                    sources=[_mk_ref(path, extracted_by, record, field=field)],
                )
            )
    return inds


def parse_dns_records(path: Path, records: List[Dict[str, Any]]) -> ParseResult:
    extracted_by = "evidence_parser:dns"
    events: List[EvidenceEvent] = []
    indicators: List[Indicator] = []

    for rec in records:
        ts = parse_timestamp(_pick(rec, ["timestamp", "time", "ts", "datetime"]))
        client_ip = _pick(rec, ["client_ip", "src_ip", "src", "ip", "client"])  # best-effort
        query = _pick(rec, ["query", "qname", "domain", "name"])
        answers = _pick(rec, ["answers", "answer", "resolved_ips", "resolved_ip", "ip_answer", "resolved"])
        server_ip = _pick(rec, ["server_ip", "resolver_ip", "dns_server"])

        # Normalize answers into list
        answer_list: List[str] = []
        if isinstance(answers, list):
            answer_list = [str(a).strip() for a in answers if str(a).strip()]
        elif isinstance(answers, str):
            answer_list = [a.strip() for a in answers.replace(";", ",").split(",") if a.strip()]
        elif answers not in (None, ""):
            answer_list = [str(answers).strip()]

        e = EvidenceEvent(
            event_type="dns_query",
            timestamp=ts,
            source=str(path),
            extracted_by=extracted_by,
            host=_pick(rec, ["host", "hostname", "device"]),
            user=_pick(rec, ["user", "username", "account"]),
            src_ip=str(client_ip) if client_ip else None,
            dst_ip=str(server_ip) if server_ip else None,
            domain=str(query) if query else None,
            action=_pick(rec, ["action", "op"]),
            outcome=_pick(rec, ["rcode", "result", "outcome"]),
            raw=rec,
            tags=["dns"],
        )
        events.append(e)

        # Indicators
        if query:
            indicators.extend(
                _extract_indicators_from_fields(
                    path,
                    extracted_by,
                    {"domain": query, "_line": rec.get("_line")},
                    ts,
                    [("domain", "domains")],
                    confidence="high",
                    tags=["dns"],
                )
            )
        if client_ip:
            indicators.append(
                Indicator(
                    indicator_type="ipv4",
                    value=str(client_ip),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="medium",
                    tags=["dns", "client"],
                    sources=[_mk_ref(path, extracted_by, rec, field="client_ip")],
                )
            )
        for ip in answer_list:
            indicators.append(
                Indicator(
                    indicator_type="ipv4",
                    value=ip,
                    first_seen=ts,
                    last_seen=ts,
                    confidence="high",
                    tags=["dns", "answer"],
                    sources=[_mk_ref(path, extracted_by, rec, field="answers")],
                )
            )

    return ParseResult(events=events, indicators=merge_indicators(indicators))


def parse_proxy_records(path: Path, records: List[Dict[str, Any]]) -> ParseResult:
    extracted_by = "evidence_parser:proxy"
    events: List[EvidenceEvent] = []
    indicators: List[Indicator] = []

    for rec in records:
        ts = parse_timestamp(_pick(rec, ["timestamp", "time", "ts", "datetime"]))
        url = _pick(rec, ["url", "uri", "request", "request_url"])
        domain = _pick(rec, ["host", "domain", "sni"])
        user_agent = _pick(rec, ["user_agent", "ua", "agent"])
        user = _pick(rec, ["user", "username", "account"])
        src_ip = _pick(rec, ["src_ip", "client_ip", "c_ip", "ip"])
        dst_ip = _pick(rec, ["dst_ip", "server_ip", "s_ip"])
        outcome = _pick(rec, ["status", "result", "outcome", "action"])

        e = EvidenceEvent(
            event_type="proxy_request",
            timestamp=ts,
            source=str(path),
            extracted_by=extracted_by,
            host=_pick(rec, ["device", "hostname", "host"]),
            user=str(user) if user else None,
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(dst_ip) if dst_ip else None,
            domain=str(domain) if domain else None,
            url=str(url) if url else None,
            outcome=str(outcome) if outcome else None,
            raw=rec,
            tags=["proxy"],
        )
        events.append(e)

        if url:
            indicators.append(
                Indicator(
                    indicator_type="urls",
                    value=str(url),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="high",
                    tags=["proxy"],
                    sources=[_mk_ref(path, extracted_by, rec, field="url")],
                )
            )
        if domain:
            indicators.append(
                Indicator(
                    indicator_type="domains",
                    value=str(domain),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="high",
                    tags=["proxy"],
                    sources=[_mk_ref(path, extracted_by, rec, field="host")],
                )
            )
        if user_agent:
            indicators.append(
                Indicator(
                    indicator_type="user_agents",
                    value=str(user_agent),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="medium",
                    tags=["proxy"],
                    sources=[_mk_ref(path, extracted_by, rec, field="user_agent")],
                )
            )
        if src_ip:
            indicators.append(
                Indicator(
                    indicator_type="ipv4",
                    value=str(src_ip),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="medium",
                    tags=["proxy", "client"],
                    sources=[_mk_ref(path, extracted_by, rec, field="src_ip")],
                )
            )
        if dst_ip:
            indicators.append(
                Indicator(
                    indicator_type="ipv4",
                    value=str(dst_ip),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="medium",
                    tags=["proxy", "server"],
                    sources=[_mk_ref(path, extracted_by, rec, field="dst_ip")],
                )
            )

    return ParseResult(events=events, indicators=merge_indicators(indicators))


def parse_firewall_records(path: Path, records: List[Dict[str, Any]]) -> ParseResult:
    extracted_by = "evidence_parser:firewall"
    events: List[EvidenceEvent] = []
    indicators: List[Indicator] = []

    for rec in records:
        ts = parse_timestamp(_pick(rec, ["timestamp", "time", "ts", "datetime"]))
        src_ip = _pick(
            rec,
            [
                "src_ip",
                "source_ip",
                "src",
                "client_ip",
                "srcip",
                "src_addr",
                "src_address",
                "source_address",
                "sourceAddress",
            ],
        )
        dst_ip = _pick(
            rec,
            [
                "dst_ip",
                "dest_ip",
                "destination_ip",
                "dst",
                "server_ip",
                "dstip",
                "dst_addr",
                "dst_address",
                "destination_address",
                "destinationAddress",
            ],
        )
        src_port = _as_int(
            _pick(
                rec,
                [
                    "src_port",
                    "sport",
                    "source_port",
                    "srcport",
                    "sourcePort",
                    "srcPort",
                ],
            )
        )
        dst_port = _as_int(
            _pick(
                rec,
                [
                    "dst_port",
                    "dport",
                    "dest_port",
                    "destination_port",
                    "dstport",
                    "destinationPort",
                    "dstPort",
                ],
            )
        )
        proto = _pick(rec, ["proto", "protocol", "ipproto", "transport", "protocol_name"])  # tcp/udp/icmp
        action = _pick(rec, ["action", "decision", "rule_action", "verdict", "disposition"])

        e = EvidenceEvent(
            event_type="network_flow",
            timestamp=ts,
            source=str(path),
            extracted_by=extracted_by,
            host=_pick(rec, ["hostname", "device", "host"]),
            user=_pick(rec, ["user", "username", "account"]),
            src_ip=str(src_ip) if src_ip else None,
            src_port=src_port,
            dst_ip=str(dst_ip) if dst_ip else None,
            dst_port=dst_port,
            proto=str(proto).lower() if proto else None,
            action=str(action) if action else None,
            outcome=str(action) if action else None,
            raw=rec,
            tags=["firewall"],
        )
        events.append(e)

        if src_ip:
            indicators.append(
                Indicator(
                    indicator_type="ipv4",
                    value=str(src_ip),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="medium",
                    tags=["firewall", "src"],
                    sources=[_mk_ref(path, extracted_by, rec, field="src_ip")],
                )
            )
        if dst_ip:
            indicators.append(
                Indicator(
                    indicator_type="ipv4",
                    value=str(dst_ip),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="medium",
                    tags=["firewall", "dst"],
                    sources=[_mk_ref(path, extracted_by, rec, field="dst_ip")],
                )
            )

    return ParseResult(events=events, indicators=merge_indicators(indicators))


def parse_vpn_records(path: Path, records: List[Dict[str, Any]]) -> ParseResult:
    extracted_by = "evidence_parser:vpn"
    events: List[EvidenceEvent] = []
    indicators: List[Indicator] = []

    for rec in records:
        ts = parse_timestamp(_pick(rec, ["timestamp", "time", "ts", "datetime"]))
        user = _pick(rec, ["user", "username", "account"])
        src_ip = _pick(rec, ["src_ip", "client_ip", "ip"])
        assigned_ip = _pick(rec, ["assigned_ip", "tunnel_ip", "vpn_ip"])
        outcome = _pick(rec, ["result", "outcome", "status"])  # success/fail

        e = EvidenceEvent(
            event_type="vpn_session",
            timestamp=ts,
            source=str(path),
            extracted_by=extracted_by,
            host=_pick(rec, ["host", "hostname", "device"]),
            user=str(user) if user else None,
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(assigned_ip) if assigned_ip else None,
            action=_pick(rec, ["action", "event"]),
            outcome=str(outcome) if outcome else None,
            raw=rec,
            tags=["vpn"],
        )
        events.append(e)

        if user:
            indicators.append(
                Indicator(
                    indicator_type="users",
                    value=str(user),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="high",
                    tags=["vpn"],
                    sources=[_mk_ref(path, extracted_by, rec, field="user")],
                )
            )
        if src_ip:
            indicators.append(
                Indicator(
                    indicator_type="ipv4",
                    value=str(src_ip),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="high",
                    tags=["vpn", "client"],
                    sources=[_mk_ref(path, extracted_by, rec, field="src_ip")],
                )
            )
        if assigned_ip:
            indicators.append(
                Indicator(
                    indicator_type="ipv4",
                    value=str(assigned_ip),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="medium",
                    tags=["vpn", "assigned"],
                    sources=[_mk_ref(path, extracted_by, rec, field="assigned_ip")],
                )
            )

    return ParseResult(events=events, indicators=merge_indicators(indicators))


def parse_auth_records(path: Path, records: List[Dict[str, Any]]) -> ParseResult:
    extracted_by = "evidence_parser:auth"
    events: List[EvidenceEvent] = []
    indicators: List[Indicator] = []

    for rec in records:
        ts = parse_timestamp(_pick(rec, ["timestamp", "time", "ts", "datetime"]))
        user = _pick(rec, ["user", "username", "account", "principal"])
        src_ip = _pick(rec, ["src_ip", "client_ip", "ip"])
        host = _pick(rec, ["host", "hostname", "computer"])
        action = _pick(rec, ["action", "event", "operation", "event_id"])
        outcome = _pick(rec, ["outcome", "result", "status"])

        e = EvidenceEvent(
            event_type="auth_event",
            timestamp=ts,
            source=str(path),
            extracted_by=extracted_by,
            host=str(host) if host else None,
            user=str(user) if user else None,
            src_ip=str(src_ip) if src_ip else None,
            action=str(action) if action else None,
            outcome=str(outcome) if outcome else None,
            raw=rec,
            tags=["auth"],
        )
        events.append(e)

        if user:
            indicators.append(
                Indicator(
                    indicator_type="users",
                    value=str(user),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="high",
                    tags=["auth"],
                    sources=[_mk_ref(path, extracted_by, rec, field="user")],
                )
            )
        if src_ip:
            indicators.append(
                Indicator(
                    indicator_type="ipv4",
                    value=str(src_ip),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="medium",
                    tags=["auth"],
                    sources=[_mk_ref(path, extracted_by, rec, field="src_ip")],
                )
            )
        if host:
            indicators.append(
                Indicator(
                    indicator_type="hostnames",
                    value=str(host),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="medium",
                    tags=["auth"],
                    sources=[_mk_ref(path, extracted_by, rec, field="host")],
                )
            )

    return ParseResult(events=events, indicators=merge_indicators(indicators))


def parse_dhcp_records(path: Path, records: List[Dict[str, Any]]) -> ParseResult:
    extracted_by = "evidence_parser:dhcp"
    events: List[EvidenceEvent] = []
    indicators: List[Indicator] = []

    for rec in records:
        ts = parse_timestamp(_pick(rec, ["timestamp", "time", "ts", "datetime"]))
        mac = _pick(rec, ["mac", "mac_address", "client_mac"])
        ip = _pick(rec, ["ip", "assigned_ip", "client_ip"])
        hostname = _pick(rec, ["hostname", "host", "client_hostname"])
        action = _pick(rec, ["action", "event", "operation"])  # lease/renew

        e = EvidenceEvent(
            event_type="dhcp_lease",
            timestamp=ts,
            source=str(path),
            extracted_by=extracted_by,
            host=str(hostname) if hostname else None,
            src_ip=str(ip) if ip else None,
            action=str(action) if action else None,
            raw=rec,
            tags=["dhcp"],
        )
        events.append(e)

        if mac:
            indicators.append(
                Indicator(
                    indicator_type="mac_addresses",
                    value=str(mac),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="high",
                    tags=["dhcp"],
                    sources=[_mk_ref(path, extracted_by, rec, field="mac")],
                )
            )
        if ip:
            indicators.append(
                Indicator(
                    indicator_type="ipv4",
                    value=str(ip),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="high",
                    tags=["dhcp"],
                    sources=[_mk_ref(path, extracted_by, rec, field="ip")],
                )
            )
        if hostname:
            indicators.append(
                Indicator(
                    indicator_type="hostnames",
                    value=str(hostname),
                    first_seen=ts,
                    last_seen=ts,
                    confidence="medium",
                    tags=["dhcp"],
                    sources=[_mk_ref(path, extracted_by, rec, field="hostname")],
                )
            )

    return ParseResult(events=events, indicators=merge_indicators(indicators))


def parse_evidence_file(path: Path, kind: str) -> ParseResult:
    """Parse a single evidence file into normalized events and indicators."""
    kind = (kind or "").strip().lower()

    # Endpoint artifacts (not CSV/JSONL logs)
    if kind in {"powershell", "powershell_history", "ps_history"}:
        events, indicators = parse_powershell_history(path)
        return ParseResult(events=events, indicators=merge_indicators(indicators))

    if kind in {"browser", "browser_history", "chrome_history", "edge_history", "firefox_history"}:
        events, indicators = parse_browser_history_sqlite(path)
        return ParseResult(events=events, indicators=merge_indicators(indicators))

    records = load_records(path)

    if kind in {"dns"}:
        return parse_dns_records(path, records)
    if kind in {"proxy"}:
        return parse_proxy_records(path, records)
    if kind in {"firewall", "flow", "netflow"}:
        return parse_firewall_records(path, records)
    if kind in {"vpn"}:
        return parse_vpn_records(path, records)
    if kind in {"auth", "login"}:
        return parse_auth_records(path, records)
    if kind in {"dhcp"}:
        return parse_dhcp_records(path, records)

    # Unknown kind: emit generic event + extract IOCs from known fields
    extracted_by = f"evidence_parser:{kind or 'generic'}"
    events: List[EvidenceEvent] = []
    indicators: List[Indicator] = []

    for rec in records:
        ts = parse_timestamp(_pick(rec, ["timestamp", "time", "ts", "datetime"]))
        e = EvidenceEvent(
            event_type=kind or "generic_record",
            timestamp=ts,
            source=str(path),
            extracted_by=extracted_by,
            host=_pick(rec, ["host", "hostname", "device"]),
            user=_pick(rec, ["user", "username", "account"]),
            src_ip=_pick(rec, ["src_ip", "client_ip", "ip"]),
            dst_ip=_pick(rec, ["dst_ip", "server_ip"]),
            domain=_pick(rec, ["domain", "qname", "host"]),
            url=_pick(rec, ["url", "uri"]),
            action=_pick(rec, ["action", "event"]),
            outcome=_pick(rec, ["outcome", "result", "status"]),
            raw=rec,
            tags=["generic"],
        )
        events.append(e)

        field_map = [
            ("src_ip", "ipv4"),
            ("dst_ip", "ipv4"),
            ("domain", "domains"),
            ("url", "urls"),
            ("user", "users"),
            ("host", "hostnames"),
        ]
        indicators.extend(
            _extract_indicators_from_fields(
                path, extracted_by, e.to_dict(), ts, field_map, confidence="low", tags=["generic"]
            )
        )

    return ParseResult(events=events, indicators=merge_indicators(indicators))


def combine_parse_results(results: List[ParseResult]) -> ParseResult:
    events: List[EvidenceEvent] = []
    inds: List[Indicator] = []
    for r in results:
        events.extend(r.events)
        inds.extend(r.indicators)
    return ParseResult(events=events, indicators=merge_indicators(inds))
