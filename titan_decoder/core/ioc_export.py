"""IOC export utilities (JSON/CSV/Minimal STIX).

Focuses on defensive sharing. STIX here is a minimal bundle sufficient for
basic indicator sharing; not a full STIX authoring suite. All exports are
best-effort and dependency-free.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List, Any, Optional


def build_ioc_summary(
    report: Dict[str, Any], forensics: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    # Extract from every node's preview, not just Text-classified ones, to
    # match TitanEngine.run_analysis: malware routinely embeds C2 URLs/IPs in
    # otherwise-binary content, and filtering on content_type silently dropped
    # them from detections, risk scoring, and exports.
    nodes = report.get("nodes", [])
    all_text = "\n".join(node.get("content_preview") or "" for node in nodes)
    from ..utils.helpers import extract_iocs

    iocs = extract_iocs(all_text)
    # Add forensic network/mobile artifacts if present
    if forensics:
        mobile = forensics.get("mobile_ids", {})
        iocs["imei"] = mobile.get("imei", [])
        iocs["imsi"] = mobile.get("imsi", [])
        iocs["iccid"] = mobile.get("iccid", [])
        net = forensics.get("network_indicators", {})
        ips = net.get("ips", []) if isinstance(net, dict) else []
        # Merge IPs
        if ips:
            merged_ips = set(iocs.get("ipv4", [])) | set(ips)
            iocs["ipv4"] = sorted(merged_ips)
    return iocs


def export_json(iocs: Dict[str, Any], path: Path):
    path.write_text(json.dumps(iocs, indent=2))


def export_csv(iocs: Dict[str, Any], path: Path):
    # Flatten into rows: type,value
    rows: List[tuple[str, str]] = []
    for key, values in iocs.items():
        for v in values:
            rows.append((key, v))
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value"])
        writer.writerows(rows)


# The "hashes" IOC bucket contains multiple digest algorithms distinguishable
# only by hex length (see helpers.extract_iocs). Exporting everything as
# SHA-256 mislabels MD5/SHA-1 values in shared threat intel.
_HASH_LEN_TO_STIX = {
    32: "MD5",
    40: "SHA-1",
    64: "SHA-256",
    128: "SHA-512",
}
_HASH_LEN_TO_MISP = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}


def export_stix_minimal(iocs: Dict[str, Any], path: Path):
    # Minimal STIX 2.1-like bundle (simplified)
    bundle: Dict[str, Any] = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000000",
        "objects": [],
    }

    def mk_indicator(ind_type: str, value: str, idx: int) -> Optional[Dict[str, Any]]:
        # STIX string literals escape backslash and single quote; without this
        # an IOC value containing a quote (e.g. a crafted URL) produces an
        # invalid STIX pattern.
        safe = value.replace("\\", "\\\\").replace("'", "\\'")
        pattern = None
        if ind_type == "ipv4":
            pattern = f"[ipv4-addr:value = '{safe}']"
        elif ind_type == "domains":
            pattern = f"[domain-name:value = '{safe}']"
        elif ind_type == "urls":
            pattern = f"[url:value = '{safe}']"
        elif ind_type == "emails":
            pattern = f"[email-addr:value = '{safe}']"
        elif ind_type == "hashes":
            algo = _HASH_LEN_TO_STIX.get(len(value))
            if algo:  # SHA-224/384 have no standard STIX vocab entry; skip
                pattern = f"[file:hashes.'{algo}' = '{safe}']"
        elif ind_type == "imei":
            pattern = f"[x-device:imei = '{safe}']"
        elif ind_type == "imsi":
            pattern = f"[x-device:imsi = '{safe}']"
        elif ind_type == "iccid":
            pattern = f"[x-device:iccid = '{safe}']"
        if not pattern:
            return None
        return {
            "type": "indicator",
            "id": f"indicator--00000000-0000-4000-8000-{idx:012d}",
            "spec_version": "2.1",
            "pattern_type": "stix",
            "pattern": pattern,
            "created": "1970-01-01T00:00:00.000Z",
            "modified": "1970-01-01T00:00:00.000Z",
            "valid_from": "1970-01-01T00:00:00.000Z",
        }

    idx = 1
    seen_patterns: set[str] = set()
    for key, values in iocs.items():
        for v in values:
            obj = mk_indicator(key, v, idx)
            if obj and obj["pattern"] not in seen_patterns:
                seen_patterns.add(obj["pattern"])
                bundle["objects"].append(obj)
                idx += 1
    path.write_text(json.dumps(bundle, indent=2))


def export_misp(
    iocs: Dict[str, Any], path: Path, event_info: str = "Titan Decoder Analysis"
):
    """Export IOCs as MISP event (JSON format)."""
    import uuid
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    event_uuid = str(uuid.uuid4())
    timestamp = int(now.timestamp())

    event: Dict[str, Any] = {
        "Event": {
            "uuid": event_uuid,
            "info": event_info,
            "date": now.strftime("%Y-%m-%d"),
            "timestamp": str(timestamp),
            "published": False,
            "analysis": "1",  # Ongoing
            "threat_level_id": "2",  # Medium
            "Attribute": [],
        }
    }

    # Map IOC types to MISP attribute types ("hashes" is resolved per-value by
    # digest length below).
    type_mapping = {
        "ipv4": "ip-dst",
        "ipv4_public": "ip-dst",
        "urls": "url",
        "domains": "domain",
        "emails": "email-src",
        "imei": "imei",
        "imsi": "imsi",
        "iccid": "sim-number",
    }

    # The IOC dict has overlapping IP buckets (ipv4 is a superset of
    # ipv4_public), so dedupe by (type, value) to avoid emitting the same
    # attribute twice.
    seen: set[tuple[str, str]] = set()
    for ioc_type, values in iocs.items():
        if ioc_type != "hashes" and not type_mapping.get(ioc_type):
            continue

        for value in values:
            if ioc_type == "hashes":
                misp_type = _HASH_LEN_TO_MISP.get(len(str(value)))
                if not misp_type:
                    continue
            else:
                misp_type = type_mapping[ioc_type]
            if (misp_type, value) in seen:
                continue
            seen.add((misp_type, value))
            attribute = {
                "uuid": str(uuid.uuid4()),
                "type": misp_type,
                "category": "Network activity"
                if misp_type in ["ip-dst", "url", "domain"]
                else "Payload delivery",
                "value": value,
                "timestamp": str(timestamp),
                "to_ids": True,
                "comment": "Extracted by Titan Decoder",
            }
            event["Event"]["Attribute"].append(attribute)

    path.write_text(json.dumps(event, indent=2))


def export_iocs(
    iocs: Dict[str, Any],
    path: Path,
    fmt: str = "json",
    event_info: str = "Titan Decoder Analysis",
):
    fmt = fmt.lower()
    if fmt == "json":
        export_json(iocs, path)
    elif fmt == "csv":
        export_csv(iocs, path)
    elif fmt == "stix":
        export_stix_minimal(iocs, path)
    elif fmt == "misp":
        export_misp(iocs, path, event_info)
    else:
        raise ValueError(f"Unsupported IOC export format: {fmt}")
