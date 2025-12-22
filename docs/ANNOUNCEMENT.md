# Titan Decoder — Announcement Templates

Use these as copy/paste posts when you share the project.

## Short (X / Mastodon)

Open-sourcing **Titan Decoder**: a payload decoding + forensic analysis engine for defenders.

- Recursive decoding (Base64/gzip/zlib/hex/XOR/etc)
- IOC extraction + exports (JSON/CSV/STIX/MISP)
- Detection rules + risk scoring
- Timeline + graph export
- IR evidence ingestion (DNS/Proxy/Firewall/VPN/Auth/DHCP exports) → normalized events + pivots
- Offline-first mode with a process-local network kill switch
- Upgradeable detections via rule packs (JSON/YAML)
- JSON schema + run manifest for stable output contracts
- JSONL export + local vault history/search

Repo: https://github.com/pragmaconflux/titan1
Quick start:
`titan-decoder --file suspicious.bin --progress --enable-detections --out report.json`

Pipeline-friendly (quiet + JSONL events):
`titan-decoder --file suspicious.bin --enable-detections --out report.json --jsonl-out events.jsonl --quiet`

## Medium (Reddit / Discord)

I’m sharing **Titan Decoder Engine** — a defensive payload decoding and forensic analysis tool.

What it does:
- Builds a decode tree (recursive Base64 + common transforms)
- Extracts IOCs (URLs/domains/IPs/emails/hashes)
- Runs starter detection rules and produces a 0–100 risk score
- Exports investigator-friendly artifacts: case report (Markdown), timeline (CSV/JSON), graph (DOT/Mermaid/JSON), MISP/STIX exports
- Supports offline-first workflows and optional enrichment
- Can store runs locally and search prior indicators (vault)

Quick start:
```bash
titan-decoder --file suspicious.bin --progress --enable-detections --out report.json
```

Investigator bundle:
```bash
titan-decoder --file evidence.bin --enable-detections --out report.json \
  --forensics-out forensics.json \
  --ioc-out iocs.json --ioc-format misp \
  --report-out case_report.md --report-format markdown \
  --timeline-out timeline.csv --timeline-format csv
```

Docs:
- Usage guide: https://github.com/pragmaconflux/titan1/blob/main/docs/USAGE.md

Feedback I’d love:
- Additional decoders/analyzers worth adding
- False positives/negatives in IOC extraction
- Detection rule ideas (defensive only)

## Long (LinkedIn)

I’m excited to share **Titan Decoder Engine**, a defensive payload decoding + forensic analysis framework designed for malware triage and investigation workflows.

Key features:
- Recursive decoding (Base64 + common layers)
- Archive and binary analyzers (ZIP/TAR/PE/ELF)
- IOC extraction with export to JSON/CSV/STIX/MISP
- Rule-based detections + a heuristic risk score for prioritization
- Investigator outputs: timeline export, graph export, Markdown case report

Repo: https://github.com/pragmaconflux/titan1
Usage guide: https://github.com/pragmaconflux/titan1/blob/main/docs/USAGE.md

If you’re in DFIR / malware analysis / blue team work, I’d love your feedback on where it’s useful and what would make it more practical.
