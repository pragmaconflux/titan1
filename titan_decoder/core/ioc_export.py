"""IOC export utilities (JSON/CSV/Minimal STIX).

Focuses on defensive sharing. STIX here is a minimal bundle sufficient for
basic indicator sharing; not a full STIX authoring suite. All exports are
best-effort and dependency-free.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Dict, List, Any


def build_ioc_summary(report: Dict[str, Any], forensics: Dict[str, Any] | None = None) -> Dict[str, Any]:
    nodes = report.get("nodes", [])
    all_text = "\n".join(node.get("content_preview", "") for node in nodes if node.get("content_type") == "Text")
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


def export_stix_minimal(iocs: Dict[str, Any], path: Path):
    # Minimal STIX 2.1-like bundle (simplified)
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000000",
        "objects": []
    }
    def mk_indicator(ind_type: str, value: str, idx: int) -> Dict[str, Any]:
        pattern = None
        if ind_type == "ipv4":
            pattern = f"[ipv4-addr:value = '{value}']"
        elif ind_type == "domains":
            pattern = f"[domain-name:value = '{value}']"
        elif ind_type == "urls":
            pattern = f"[url:value = '{value}']"
        elif ind_type == "emails":
            pattern = f"[email-addr:value = '{value}']"
        elif ind_type == "hashes":
            pattern = f"[file:hashes.'SHA-256' = '{value}']"
        elif ind_type == "imei":
            pattern = f"[x-device:imei = '{value}']"
        elif ind_type == "imsi":
            pattern = f"[x-device:imsi = '{value}']"
        elif ind_type == "iccid":
            pattern = f"[x-device:iccid = '{value}']"
        if not pattern:
            return None
        return {
            "type": "indicator",
            "id": f"indicator--00000000-0000-4000-8000-{idx:012d}",
            "spec_version": "2.1",
            "pattern_type": "stix",
            "pattern": pattern,
        }

    idx = 1
    for key, values in iocs.items():
        mapped_key = key
        if key == "domains":
            mapped_key = "domains"
        for v in values:
            obj = mk_indicator(mapped_key, v, idx)
            idx += 1
            if obj:
                bundle["objects"].append(obj)
    path.write_text(json.dumps(bundle, indent=2))


def export_misp(iocs: Dict[str, Any], path: Path, event_info: str = "Titan Decoder Analysis"):
    """Export IOCs as MISP event (JSON format)."""
    import uuid
    from datetime import datetime
    
    event_uuid = str(uuid.uuid4())
    timestamp = int(datetime.utcnow().timestamp())
    
    event = {
        "Event": {
            "uuid": event_uuid,
            "info": event_info,
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "timestamp": str(timestamp),
            "published": False,
            "analysis": "1",  # Ongoing
            "threat_level_id": "2",  # Medium
            "Attribute": []
        }
    }
    
    # Map IOC types to MISP attribute types
    type_mapping = {
        "ipv4": "ip-dst",
        "ipv4_public": "ip-dst",
        "urls": "url",
        "domains": "domain",
        "emails": "email-src",
        "hashes": "sha256",
        "imei": "imei",
        "imsi": "imsi",
        "iccid": "sim-number",
    }
    
    for ioc_type, values in iocs.items():
        misp_type = type_mapping.get(ioc_type)
        if not misp_type:
            continue
        
        for value in values:
            attribute = {
                "uuid": str(uuid.uuid4()),
                "type": misp_type,
                "category": "Network activity" if misp_type in ["ip-dst", "url", "domain"] else "Payload delivery",
                "value": value,
                "timestamp": str(timestamp),
                "to_ids": True,
                "comment": "Extracted by Titan Decoder",
            }
            event["Event"]["Attribute"].append(attribute)
    
    path.write_text(json.dumps(event, indent=2))


def export_iocs(iocs: Dict[str, Any], path: Path, fmt: str = "json", event_info: str = "Titan Decoder Analysis"):
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
