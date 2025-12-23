# Titan Decoder: Practical Usage Guide

This guide explains how to *use* Titan Decoder day-to-day: what the commands do, what to watch for in the output, and how to interpret the JSON report.

## What Titan Decoder does (mental model)

Titan Decoder takes a blob of bytes (a file), then repeatedly:

1. Treats the current blob as a **node**.
2. Tries to identify container formats first (ZIP/TAR/PE/ELF analyzers).
3. If not a container, tries a set of **decoders** (Base64/recursive Base64, gzip, zlib, hex, XOR, etc.).
4. Picks the **best** decode attempt using a heuristic **decode_score**.
5. Repeats recursively until it hits resource limits (depth/node count/size) or there’s nothing worth decoding.

The output is an **analysis tree** of nodes. Each node has a short text preview (when it looks like text), which is used for IOC extraction and lightweight forensics.

## Install / Run

From the repo root:

- Editable install (recommended while you’re developing):

  - `pip install -e .`

- Optional enrichment dependencies:

  - `pip install -r requirements-optional.txt`

Run the CLI:

- `titan-decoder --help`

If `titan-decoder` isn’t on your PATH yet, you can run:

- `python -m titan_decoder.cli --help`

## The 3 “starter” commands (copy/paste)

### 1) Basic: analyze one file → JSON report

- `titan-decoder --file suspicious.bin --out report.json`

### 2) Triage: show progress + run detections/risk scoring

- `titan-decoder --file suspicious.bin --out report.json --progress --enable-detections`

### 3) Investigator bundle: IOCs + timeline + case report + forensics

- `titan-decoder --file evidence.bin --enable-detections \
  --out report.json \
  --forensics-out forensics.json \
  --ioc-out iocs.json --ioc-format misp \
  --report-out case_report.md --report-format markdown \
  --timeline-out timeline.csv --timeline-format csv`

Optional output modes:

- Include a decision trace in the JSON report (helpful for debugging scoring/pruning):
  - `titan-decoder --file suspicious.bin --trace --out report.json`

- Save a shareable HTML case report:
  - `titan-decoder --file evidence.bin --report-out case_report.html --report-format html`

- Stream newline-delimited JSON events (easy ingestion into other tools):
  - `titan-decoder --file suspicious.bin --out report.json --jsonl-out events.jsonl --enable-detections --quiet`

- Run a self-check (prints a JSON diagnostic report; great for bug reports):
  - `titan-decoder --doctor`

- Store runs locally and search later (IOC/value history):
  - Store: `titan-decoder --file suspicious.bin --out report.json --vault-store --quiet`
  - Search: `titan-decoder --vault-search http://example.com`
  - Search only a specific IOC type: `titan-decoder --vault-search http://example.com --vault-search-type urls`
  - List recent runs: `titan-decoder --vault-list-recent 20`
  - Prune old runs: `titan-decoder --vault-prune-days 30`

- Quiet mode (keeps stdout/stderr clean for pipelines):
  - `titan-decoder --file suspicious.bin --out report.json --quiet`

CI/pipeline mode:

- Fail the process if risk is HIGH/CRITICAL (non-zero exit code):
  - `titan-decoder --file suspicious.bin --enable-detections --fail-on-risk-level HIGH --out report.json`

Offline mode:

- Default recommendation: run offline unless you explicitly need enrichment.
- Force offline even if your config enables enrichment:
  - `titan-decoder --file suspicious.bin --offline --out report.json`
- If you pass both `--enable-enrichment` and `--offline`, Titan will skip enrichment.

Note: `--offline` also enables a best-effort process-local network kill switch (blocks outbound socket calls) to reduce the risk of accidental network access.

Enrichment caching:

- When enrichment is enabled, Titan can use a local SQLite cache to make enrichment results repeatable across runs.
- Set a cache location explicitly (recommended for CI/workspaces):
  - `titan-decoder --file suspicious.bin --enable-enrichment --enrichment-cache-path ./enrichment_cache.db --out report.json`
- Force a refresh (bypass cache) if you need to re-query providers:
  - `titan-decoder --file suspicious.bin --enable-enrichment --refresh-enrichment --out report.json`

## IR evidence ingestion (A/B/C workflows)

If you have **network/security logs** and **endpoint artifact exports** in addition to the suspicious payload, you can ingest those into Titan as normalized **events** and **indicators**.

This enables:

- Evidence-backed **first_seen/last_seen** tracking (within the evidence you provided)
- **Top pivots**: indicators that are frequent, recent, and/or multi-source
- A single handoff report that combines payload triage + logs

### Add evidence files

Use `--evidence KIND:PATH` (repeatable). Supported formats: `.csv`, `.jsonl`, `.ndjson`.

Supported `KIND` values:

- `dns`
- `proxy`
- `firewall` (or `flow`/`netflow`)
- `vpn`
- `auth`
- `dhcp`
- `powershell_history` (PSReadLine history text)
- `browser_history` (SQLite: Chrome/Edge History, Firefox places.sqlite)
- `generic` (best-effort mapping)

Example:

```bash
titan-decoder --file suspicious.bin --out report.json --enable-detections \
  --evidence dns:./logs/dns.csv \
  --evidence proxy:./logs/proxy.csv \
  --evidence firewall:./logs/flows.csv \
  --evidence auth:./logs/auth.jsonl \
  --report-out case_report.md --report-format markdown
```

Export a normalized evidence timeline (from the ingested `--evidence` sources):

```bash
titan-decoder --file suspicious.bin --out report.json \
  --evidence proxy:./logs/proxy.csv \
  --evidence-timeline-out evidence_timeline.csv --evidence-timeline-format csv
```

### Minimal field expectations (best-effort)

Titan does not require a strict vendor schema. It uses common column/field names when available.

- **DNS** (CSV/JSONL): `timestamp`, `client_ip`, `query`, `answers`
- **Proxy**: `timestamp`, `src_ip`, `url`, `user_agent`, `user` (optional)
- **Firewall/Flows**: `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `action`
- **VPN**: `timestamp`, `user`, `src_ip`, `assigned_ip`, `result`
- **Auth**: `timestamp`, `user`, `src_ip`, `host`, `outcome`
- **DHCP**: `timestamp`, `mac`, `ip`, `hostname`, `action`

Timestamps can be ISO strings, epoch seconds, or common `YYYY-mm-dd HH:MM:SS` formats. Unknown fields are preserved in `event.raw`.

### Where it shows up in the report

When evidence is ingested, the main JSON report includes a top-level `evidence` section:

- `evidence.events`: normalized event records
- `evidence.indicators`: indicators with provenance (sources) and confidence
- `evidence.last_seen`: summary mapping for rapid pivoting
- `evidence.top_pivots`: the top 10 pivots (multi-source / recent)
- `evidence.entity_hints`: grouped hints (infra, identity, assets)

Evidence indicators are also merged into the `iocs` summary used for exports (`--ioc-out`) and rule detections (`--enable-detections`).

## Detection rule packs (rules-as-data)

Titan ships with built-in starter detections, but you can add custom detections without changing code by loading a **rule pack**.

### Example rule pack (JSON)

Save as `my_pack.json`:

```json
{
  "schema_version": 1,
  "pack": {"name": "My Pack", "version": "0.1.0"},
  "rules": [
    {
      "id": "MY-001",
      "name": "Mentions PowerShell",
      "description": "Detects PowerShell strings in decoded previews",
      "severity": "medium",
      "type": "content_regex",
      "pattern": "powershell",
      "flags": ["IGNORECASE"]
    },
    {
      "id": "MY-002",
      "name": "Has URLs and public IPs",
      "description": "Basic infra indicators",
      "severity": "high",
      "type": "ioc_present",
      "ioc_types": ["urls", "ipv4_public"],
      "min_each": 1
    }
  ]
}
```

Run with the pack:

- `titan-decoder --file suspicious.bin --enable-detections --rules-pack ./my_pack.json --out report.json`

Notes:

- YAML packs are also supported (`.yml`/`.yaml`) when PyYAML is installed (see `requirements-optional.txt`).
- Pack provenance is recorded in `report.meta.rule_packs` and each detection includes a `source` field.

## First 10 minutes (beginner checklist)

If you understand the *concept* but aren’t sure how to operate the tool, use this exact workflow:

1. Run a triage analysis:
  - `titan-decoder --file <sample> --out report.json --progress --enable-detections`
2. Open `report.json` and answer these 4 questions:
  - How deep did it go? (look at max `depth` in `nodes`)
  - Did any decoder get a good score? (look for high `decode_score`)
  - Do the previews become readable script/URLs/commands anywhere?
  - What IOCs were extracted? (look at `iocs`)
3. If it looks “too shallow” (few nodes), re-run deeper:
  - `titan-decoder --file <sample> --profile full --out report.json --enable-detections`
4. If it looks “too noisy/too slow”, re-run fast:
  - `titan-decoder --file <sample> --profile fast --out report.json --enable-detections`

This is the fastest path from “I don’t know what I’m seeing” to “I have a lead.”

## Quick triage: 30-second report cheat-sheet

These commands help you quickly answer “where is the interesting content?” without manually scrolling thousands of lines.

### Show the highest-depth nodes

- `python - <<'PY'
import json
r=json.load(open('report.json'))
nodes=r.get('nodes',[])
top=sorted(nodes,key=lambda n:n.get('depth',0),reverse=True)[:10]
for n in top:
   print(n.get('id'), 'depth=',n.get('depth'), 'decoder=',n.get('decoder_used'), 'score=',round(n.get('decode_score',0),3))
PY`

### Show the best-scoring nodes (usually “best decode wins”)

- `python - <<'PY'
import json
r=json.load(open('report.json'))
nodes=r.get('nodes',[])
top=sorted(nodes,key=lambda n:n.get('decode_score',0),reverse=True)[:10]
for n in top:
   preview=(n.get('content_preview') or '').replace('\n',' ')[:120]
   print(n.get('id'), 'depth=',n.get('depth'), 'decoder=',n.get('decoder_used'), 'score=',round(n.get('decode_score',0),3), 'preview=',preview)
PY`

### Print just the IOC summary

- `python - <<'PY'
import json
r=json.load(open('report.json'))
iocs=r.get('iocs',{})
for k,v in iocs.items():
   if v:
      print(f"{k}: {len(v)}")
PY`

### Print detections + risk (if enabled)

- `python - <<'PY'
import json
r=json.load(open('report.json'))
print('risk_assessment:', r.get('risk_assessment'))
print('detections:', r.get('detections'))
PY`

## Batch mode (whole directory)

Analyze many files and produce one report per file:

- `titan-decoder --batch ./input_dir --batch-pattern "*.bin" --out ./reports`

Output example per file:

- `./reports/<filename>_report.json`

## Profiles (fast vs full)

Profiles are presets that tweak recursion and resource usage:

- `--profile fast`
  - Sets `max_recursion_depth=3`
  - Sets `max_node_count=50`
  - Disables parallel extraction

- `--profile full`
  - Sets `max_recursion_depth=8`
  - Sets `max_node_count=200`
  - Enables parallel extraction

You can override these explicitly:

- `--max-depth 6`
- `--max-artifacts 120`

## What to look for in console output

### The useful “summary footer”
After each run, the CLI prints a summary like:

- **Nodes Generated**: how many nodes were created in the decode tree.
- **IOCs Found**: total count across all IOC categories.
- **Detections** / **Risk Level**: only when you used `--enable-detections`.

If you prefer machine-friendly output with minimal console noise (or you’re piping stdout), use `--quiet` to suppress this footer and other non-error status messages.

If you see *very few nodes* but *high entropy* and *little decoding*, that often means the input is:

- encrypted
- packed
- compressed with an unsupported algorithm
- XOR’d with a key that isn’t discovered

If you see *many nodes* and deep depth, that often means:

- heavy obfuscation (many layers)
- nested Base64 (common in malicious scripts)

## What “translate” means in practice

People often say “what should I translate?” when they really mean:

- Which decoded layer is the *real payload* vs noise?
- Which strings are meaningful vs random?

In Titan, your “translation surface area” is mostly:

- `content_preview` on the nodes that have the highest `decode_score` and/or highest `depth`.

Typical things to translate/interpret from previews:

- PowerShell/CMD/JS/VBS commands (execution flow)
- URLs/domains/IPs (infrastructure)
- `MZ` / `ELF` / suspicious headers (embedded executable)
- Encoded blobs that look like Base64 again (nested obfuscation)

## Understanding the JSON report

The main report file (`--out report.json`) is the thing you’ll inspect most.

Top-level keys:

- `meta`: tool name + version
- `node_count`: number of nodes
- `nodes`: the analysis tree flattened into a list
- `iocs`: extracted indicators (URLs, IPs, domains, emails, hashes)
- `detections` (only when `--enable-detections`): which rules triggered
- `risk_assessment` (only when `--enable-detections`): 0–100 score + reasons

### Node fields (what they mean)
Each entry in `nodes` includes:

- `id`: node id (0 is the root)
- `parent`: parent node id (null for root)
- `depth`: how many decode steps deep (0, 1, 2…)
- `method`: what happened at this node
  - `ANALYZE` means “normal analysis node”
  - `ANALYZE_ZIP`, `ANALYZE_TAR` etc means an analyzer extracted content
- `decoder_used`: which decoder/analyzer was selected as “best”
- `decode_score`: heuristic confidence that the decode was meaningful
- `entropy`: Shannon entropy (roughly: randomness)
  - ~0–5: usually text / structured
  - ~7.5–8.0: often encrypted/packed/compressed
- `content_type`: `Text` or `Binary` (based on UTF-8 decodeability)
- `content_preview`: first ~2000 bytes as UTF-8 (errors ignored)
- `pruned`: node was cut off by pruning/resource logic

### What “pruned” means (important)

If `pruned: true`, Titan is telling you it intentionally stopped exploring that branch to stay safe/fast.

Common reasons:

- too deep (hit `max_recursion_depth`)
- too many nodes (hit `max_node_count`)
- too large (hit `max_data_size`)
- low-quality decode attempts (low `decode_score`)
- duplicate content (hash deduplication)

If you think pruning hid something important, re-run with `--profile full`, or raise `--max-depth` / `--max-artifacts`.

### How to “follow the trail” to the payload
A practical workflow:

1. Start at the root node: `nodes[0]`.
2. Look for nodes with:
   - higher `decode_score`
   - increasing `depth`
   - `content_type == "Text"`
   - previews that suddenly look like script, URLs, commands, or a PE header (`MZ`)
3. If you get to a node where previews show:
   - PowerShell / cmd / mshta / wscript strings
   - URLs/domains/IPs
   - “MZ” / “ELF”
   …that’s usually the real “decoded” payload.

## IOC extraction (what “translate” means here)

Titan extracts IOCs primarily from **text previews** across all nodes.

The `iocs` object typically includes:

- `urls`: `http://` / `https://` links
- `domains`: domain-like strings
- `ipv4_public` vs `ipv4_private`
- `emails`
- `hashes`: hex strings (MD5/SHA1/SHA256…)

Notes:

- The extractor tries to handle percent-encoding (e.g. `%2F`) so you still catch real URLs.
- Domains are lowercased.
- It can over-match sometimes (any hex blob can look like a “hash”). Treat as leads, not proof.

## Detections + risk scoring

Enable with:

- `--enable-detections`

What happens:

- **Detections**: rule-based flags like:
  - deep Base64 nesting
  - Office OLE with network indicators
  - XOR + network indicators
  - malicious PDF signatures

- **Risk assessment**:
  - `risk_score`: 0–100
  - `risk_level`: CLEAN / LOW / MEDIUM / HIGH / CRITICAL
  - `top_reasons`: human-readable reasons

This is meant for *triage* (what to prioritize), not a courtroom-grade conclusion.

## Common beginner gotchas

- “My report has no `risk_score` / detections”
  - You must run with `--enable-detections`.
- “I can’t find the decoded bytes”
  - Titan stores previews + metadata, not full extracted payload bytes. Use it to *identify* the interesting layer, then extract the bytes via your own workflow (or extend the engine to export full artifacts).
- “I’m seeing domains like `2fcdn.example` or other weird stuff”
  - IOC extraction is best-effort; validate indicators before acting.
- “Everything is binary, no IOCs”
  - Many malware blobs won’t contain readable strings; try `--profile full` and export a graph/timeline to understand where decoding stops.

## Logging privacy (redaction)

PII redaction in logs is enabled by default.

- To disable it (e.g., in a private lab where you want raw logs): `titan-decoder --no-redaction ...`

The report JSON itself may still contain strings in `content_preview`, so treat the report as sensitive.

## Safe handling (quick reminder)

When analyzing unknown/malicious samples:

- Prefer a VM or isolated environment.
- Don’t execute or “open” decoded content with tools that might run macros/scripts.
- Treat exported reports/IOCs as sensitive artifacts (they can contain PII or incident data).

## Forensics summary

Use either:

- `--forensics-print` to see it in stdout
- `--forensics-out forensics.json` to save it

It scans node previews for defensive attribution hints:

- VM artifacts (VirtualBox/VMware/KVM/Hyper-V)
- mobile identifiers (IMEI/IMSI/ICCID)
- “burner” hostname patterns
- timezone hints

## Timeline export

- `--timeline-out timeline.json`
- `--timeline-out timeline.csv --timeline-format csv`

This is a simple ordered list of nodes, good for spreadsheets or quick audits.

## Graph export (visualize the decode tree)

- `--graph graph.json --graph-format json`
- `--graph graph.dot --graph-format dot`
- `--graph graph.mmd --graph-format mermaid`

If you export DOT you can render with Graphviz, and Mermaid can be pasted into Markdown viewers that support Mermaid.

## Configuration (when you feel lost)

Titan loads config from:

- `~/.titan_decoder/config.json`

Useful knobs:

- `max_recursion_depth`: how deep to keep decoding
- `max_node_count`: maximum nodes/artifacts
- `max_data_size`: input size safety limit
- `decoders`: enable/disable specific decoders
- `analyzers`: enable/disable ZIP/TAR/PE/ELF analyzers

## Practical troubleshooting

- “It stops too early” → increase `--max-depth` or `max_recursion_depth`.
- “It’s too slow / explodes with nodes” → use `--profile fast` or lower `max_node_count`.
- “Nothing decodes, entropy stays high” → it may be encrypted/packed; focus on IOCs in early layers and the file context (where it came from).
- “IOCs are empty” → try `--profile full` and check if any nodes are `Text` and have readable previews.
