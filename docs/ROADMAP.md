# Titan Decoder Engine Roadmap

This roadmap separates shipped features from planned work.

## Current priority: depth before breadth

Major feature-surface expansion is paused while Titan deepens its shipped
capabilities. The ordered measurement, corpus, parser, fuzzing, code-assurance,
operational, and independent-validation work is tracked in
[DEPTH_HARDENING.md](DEPTH_HARDENING.md). The enterprise-competitiveness items
below remain useful context, but unfinished breadth items are deferred until the
depth program's foundations and assurance ratchets are established.

## Shipped

- Recursive decoder/analyzer graph
- Provenance, hashes, entropy, and transformation confidence
- Structural PDF and OLE/CFB parsing
- IOC extraction and evidence ingestion
- Detection rules and risk scoring
- Resource limits and offline guard
- Deterministic Intelligence Layer
- Intelligence v1.0 schema, compatibility tests, and calibration corpus
- Intelligence in Markdown/HTML case reports
- Intelligence annotations in JSON/DOT/Mermaid graph exports
- Evidence-backed MITRE ATT&CK mappings, LOLBin identification, and behavioral malware tags (Threat Intelligence Engine)
- ATT&CK technique metadata (`attack_ids`) on built-in detection rules and rule packs
- Expanded 48-technique ATT&CK catalog subset with matching behavior and LOLBin rules
- Threat-intelligence precision hardening and calibration corpus with CI gate
- Catalog/producer parity: every ATT&CK catalog entry has a built-in producer or an explicit rule-pack-only designation
- Repeatable performance benchmarks with a committed baseline and CI regression gate
- Rule-pack hardening: enforced validation, duplicate-ID checks (including built-in impersonation), per-pack limits, fixtures, and a strict `--rules-validate` gate
- Evidence correlation platform (Milestone 5): cross-case IOC database, relationship scoring, campaign clustering, timeline correlation, infrastructure reuse detection, shared payload detection, attribution hints, analyst views, persisted cross-case fingerprints/events, and `--correlation-search`

- Plugin SDK v1 (Milestone 6): stable public decoder/analyzer/detection/report APIs behind `titan_decoder.plugins.api`, plugin manifest with JSON Schema, semantic version compatibility and dependency constraints, deep validation (`--plugin-validate`), example plugins, and a complete developer guide
- Analyst Workbench (Milestone 7): `titan workbench` terminal application — report library, decode-tree and interactive graph exploration with node navigation, IOC/detection/timeline/evidence browsers, correlation view, ranked cross-report search, investigation workspaces with notes/tags/status, and CSV/graph/ZIP-bundle exports
- Local AI Analyst (Milestone 8): `titan analyst` — report-grounded evidence ledger with stable citations, deterministic question planning, citation-enforced validation, a tested local OpenAI-compatible backend (loopback-only by default), and a deterministic no-model default that doubles as the guaranteed fallback

Additional shipped engine expansion:

- ASCII85, Base58, Base91, raw Deflate, PowerShell EncodedCommand,
  JavaScript escape, and optional Brotli/Zstandard decoders.
- RFC/MIME, OOXML, script, LNK, optional 7z/RAR/ISO/CAB, deeper PE/ELF, and
  expanded image/audio/video steganography analyzers.
- Versioned Windows/Debian capability handshake, manual decoder parity,
  progress events, real timeouts, and cancellation.
- Hash-bound assurance adapters for isolated VM and provenance providers plus
  optional native Authenticode verification.
- Out-of-process manifest-plugin execution with resource bounds, offline
  network policy, and permission-scoped configuration disclosure.
- Deterministic Deep Scan, per-file assurance reports, and hash-addressed,
  recoverable, copy-by-default quarantine.
- Decoder/analyzer calibration v1 with a labeled corpus, confusion matrices,
  per-component metrics, and precision/recall gates.

## Highest-value next work

The original milestone plan and the engine-expansion pass are complete. Future
work should be driven by measured misses: larger representative calibration
corpora, OS-native sandbox adapters for plugin workers, additional signed-file
formats, richer memory-image analysis, and provider-specific VM integrations.
Any new parser or decoder should land with a labeled positive/negative corpus
slice and resource-bound regression tests.

## Enterprise-competitiveness track

Ordered by leverage. Each item ships incrementally behind Titan's existing
constraints: deterministic, bounded, offline-first, fail-closed.

1. **Detection content at scale.** YARA scanning of every artifact-graph
   node shipped (see DETECTION_AND_RISK.md). The starter pack now includes
   precision-tested remote certutil download, MSHTA execution, and regsvr32
   scriptlet chains in addition to its decoded-content signatures. Every
   starter rule now has multiple labeled positives, adversarial benign
   near-misses, committed precision/recall metrics, and a CI quality gate;
   next: grow the corpus and rule library with measured field-derived misses.
2. **Malware config extraction.** Family identification plus C2/config
   recovery (addresses, keys, campaign ids) now has a documented API 1.2
   extractor SDK, isolated-worker transport, validation, report integration,
   and bounded seed extractors for Cobalt Strike Beacon and decrypted Remcos
   settings, with real-layout positive/adversarial fixtures. Next: expand the
   calibrated family and version matrix from measured field samples.
3. **Format coverage depth.** MSI table/custom-action evidence, OneNote, RTF
   exploit structures, Excel 4.0 XLM macros, PDF stream filters with JavaScript
   extraction, APK/DEX, bounded VHD/VHDX structure inspection, PE-hosted .NET
   assembly/resource metadata, NSIS/Inno overlay identification, and bounded
   password-protected ZIP extraction (`infected`) now ship with adversarial
   coverage and explicit resource limits. Small self-contained VHDX images now
   also have bounded BAT reconstruction and MBR/GPT partition recovery. Next:
   VBA p-code, large/differencing virtual-disk and file-system recovery, and
   full NSIS/Inno payload-table decompression, prioritized by measured misses.
4. **Service mode.** A `titan server` deployment shape: REST API, work
   queue, horizontally scalable workers, artifact store, and hash-based
   dedup cache now ships as a dependency-free, loopback-only-by-default
   reference deployment. Next: production queue/object-store adapters and
   deployment manifests for multi-host operation.
5. **Bounded emulation.** Instruction-budgeted, no-I/O emulation for
   shellcode and sandboxed JavaScript evaluation for deobfuscation now has a
   fail-closed foundation: a constant-only JavaScript interpreter plus an x86
   register/stack interpreter that blocks memory, system, and extended
   instructions. Next: expand opcode and language coverage only alongside
   adversarial corpus cases and the existing hard budgets.
6. **Proof and ecosystem.** Published benchmark runs against public corpora,
   a public accuracy dashboard fed by calibration output, MISP/STIX export,
   and a provenance-pinned offline community plugin catalog now ship with a
   deterministic CI freshness gate. The fuzz-backed parser inventory and
   source-hash manifest are ready for independent review; publishing an actual
   third-party assessor and report remains an external attestation step,
   tracked as outreach rather than engineering because no internal work
   advances it (see [DEPTH_HARDENING.md](DEPTH_HARDENING.md) D8).
   Positioning: forensic-grade, deterministic, offline-first, court-ready
   provenance.

## Local AI assistant (shipped as Milestone 8)

The requirements that guided the design — optional and disabled by
default, local/offline first, no autonomous network access, facts
separated from model inference, bounded input/output/time, graceful
deterministic fallback, and one fully working backend before multiple
adapters — are all implemented; see
[LOCAL_AI_ANALYST.md](LOCAL_AI_ANALYST.md). Additional backends (e.g.
ONNX with a concrete model and tokenizer contract) can be added behind
the existing `AnalystBackend` interface.
