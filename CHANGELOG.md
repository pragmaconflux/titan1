# Changelog

## Unreleased

Bound enforcement honesty:

- Report `operation_timeout_unenforced` and `memory_bound_unenforced` as run
  limitations where the host cannot enforce an advertised bound, instead of
  degrading silently. Per-operation timeouts rely on SIGALRM, which is
  POSIX-and-main-thread-only, so the desktop UI's analysis thread has none on
  any platform.
- Measure memory with `resource.getrusage` when psutil is absent, so the common
  headless install keeps a real ceiling. `check_memory_usage` now returns
  `None` rather than `0.0` when memory cannot be measured at all; `0.0`
  silently satisfied every configured limit while still appearing enforced.

Host-embedded corpus:

- Derive a host-embedded variant of every decoder positive case and run it
  through the engine, so decoder selection and carving are both measured.
  Every previous calibration fixture is a whole-buffer case, which is why a
  corpus reporting 1.0 precision and recall coexisted with a dropper that
  produced no indicators.
- Record the misses as a two-way contract: a new miss fails as a regression,
  and a fixed miss fails until it is removed from the recorded list.
- Recognize compressed and structured binary in the carving gate (zlib, raw
  DEFLATE via bounded trial inflation, Zstandard, 7-Zip, OLE/CFB, and UTF-16
  text), raising host-embedded recovery from 17/26 to 22/26. The gate stays
  local to carving so transport decoders' output checks are unchanged.
- Four misses remain recorded with reasons: two payloads below the minimum
  carve run length, Brotli's headerless streams, and a decoder-selection
  conflict where Base64 outranks Hex on identical input.

Domain IOC precision:

- Require domain indicators to end in a recognized TLD, validated against a
  committed verbatim snapshot of IANA's root-zone list plus the RFC-reserved
  names (`.example`, `.invalid`, `.local`, `.localhost`, `.onion`, `.test`).
  The previous denylist could not scale: JavaScript member access
  (`WScript.Shell`), COM ProgIDs (`ADODB.Stream`), and labels fused to
  adjacent binary (`payload.binPK`, from a ZIP central directory) were all
  reported as domains, and fed risk scoring, intelligence signal counts, and
  cross-case infrastructure correlation.
- Filter COM/scripting object ProgIDs by their *leading* label, since `.shell`,
  `.stream`, `.run`, `.call`, and `.network` are genuinely delegated TLDs —
  `wscript.shell` is dropped while an ordinary `acme.shell` is kept.
- An unreadable snapshot fails open, so losing the data file can never silently
  delete every domain indicator from a report.
- Benign corpus risk scores drop (fabricated domains no longer inflate them)
  and rule precision/recall are unchanged; metrics, goldens, and the proof
  bundle are regenerated.

Embedded-payload carving:

- Add an `EmbeddedPayload` analyzer that carves encoded regions (base64,
  base64url, hex) out of *host* files and emits each as a child artifact with
  its byte offset recorded in provenance. Titan's decoders are whole-buffer
  transforms, so a payload previously only decoded when the artifact *was* the
  encoded blob; the ordinary shape of a real dropper — a base64 blob assigned
  to a script variable — decoded to nothing and the chain stopped at the host.
- Carving *composes*: it runs in addition to the format analyzer that claims
  the node rather than consuming the single analyzer slot, so a script is
  still script-analyzed while its embedded blob is carved out. Analyzers
  declare this with the new `Analyzer.composes` property.
- Candidates are only emitted when they clear a minimum run length, decode
  cleanly, and produce output that looks like a real payload, so benign
  alphabet runs and high-entropy noise are declined rather than reported.
  Bounded by `max_carved_artifacts`, `max_carved_artifact_size`,
  `max_carved_total_size`, `max_carve_scan_bytes`, and `min_carved_run_length`.
- Provenance records `origin: "carve"`, the producing pass, and
  `source_offset` for every carved artifact.

IOC extraction correctness:

- Extract indicators from each artifact's full retained content instead of its
  2KB `content_preview` excerpt. Any URL, IP, domain, email, or hash past byte
  2000 of a node was previously invisible to the IOC stage even though the
  bytes were retained — a 10KB script with its C2 on the last line reported no
  indicators at all.
- Bound the new scan with `max_ioc_scan_bytes` (default 1MB per node) so the
  wider window stays proportional to the node cap.

Determinism and compatibility:

- Verify golden reports, root/lineage commitments, and frozen compatibility
  fixtures on Windows across Python 3.10–3.13 in addition to the Linux matrix.
- Lock legacy report, workspace, and Plugin API 1.0 reader behavior, including
  `parent_id` navigation, and publish an explicit contract migration matrix.

Code-assurance ratchet:

- Raise the CI coverage floor from 70% to 75% while keeping the full package in
  scope.
- Remove `core.evidence_parsers` from the mypy exemption list and add property
  checks for evidence ordering, deduplication, record bounds, and coercion.

Continuous adversarial testing:

- Add a weekly 30-minute fuzz campaign spanning decoder/analyzer contracts,
  evidence parsers, plugin transport, server request bounds, report loading and
  exports, and workspace loading.
- Retain machine-readable campaign metrics and deletion-minimized reproducers
  as CI artifacts for 30 days, with recorded seeds for replay.

Detection content depth:

- Add native `TITAN-009` and starter-pack YARA coverage for suspicious
  logon/startup scheduled-task persistence (`T1053.005`).
- Measure command-line and PowerShell behavior variants, decoded-child
  coverage, multi-rule risk stacking, and benign administrative lookalikes.

Decoder calibration depth:

- Require every live built-in decoder, as well as every structural analyzer,
  to carry deterministic malformed and truncated calibration cases.
- Add compact derived-case mutations with pinned extraction hashes so a corpus
  can retain its original fixture while measuring corrupt and partial variants.

## 2.1.0 — Depth, extensibility, and analyst workflows (2026-08-29)

Detection-depth hardening:

- Derive detection-quality coverage from the live built-in rule registry so a
  new `TITAN-*` rule cannot silently ship without published calibration.
- Expand the deterministic labeled corpus from 27 to 43 cases, add two positive
  and two targeted benign near-miss cases for `TITAN-008`, and require every
  built-in rule to maintain at least two of each.
- Make the evaluator fail closed on precision, recall, corpus coverage, label
  integrity, duplicate samples, missing decoder preconditions, targeted
  near-miss, or risk-separation regressions.
- Stop treating routine `-NoProfile`, `cmd.exe /c`, and `cscript //nologo`
  administration—or the benign `-Encoding` option—as LOLBin abuse by
  themselves, and stop joining LOLBin context across unrelated nodes.
- Require executable or packer context for `TITAN-004`, keeping ordinary
  ciphertext as an entropy risk signal instead of a detection false positive.
- Keep Base64, OLE, XOR, and PDF evidence on the same artifact lineage; require
  actual macro markers for OLE detections, binary magic rather than prose for
  PDF detections, and C2/beacon/exfiltration context for multi-IOC detections.
- Publish built-in detection counts and per-rule corpus depth in the proof
  dashboard.

First-class YARA integration:

- Scan every artifact-graph node — raw, decoded, and extracted content —
  with configured YARA rules during the detection stage, so signatures
  match content that a scan of the raw input alone would never see.
- Add `--yara-rules` (repeatable, file or directory) and configuration keys
  for rule files, rule directories, and scan bounds (per-payload timeout,
  node/match caps, bounded meta and matched-string capture).
- Compile rule directories with one namespace per file, report matches in
  deterministic order, and persist the fail-closed scan result as the
  report's `yara` section.
- Convert matches into `YARA:<namespace>:<rule>` detections (grouped per
  rule with all matched node ids, severity and ATT&CK ids from rule meta)
  that feed risk scoring, which now receives the previously-unused YARA
  weighting input.
- Route assurance's static YARA control through the same shared scanner,
  giving Deep Scan and assurance rule-directory support and bounded
  capture for free.
- Keep YARA active under `--offline`: it is a purely local scan and no
  longer disabled alongside network enrichment providers.
- Ship a starter rule pack in `examples/yara_rules/` tuned for per-node
  scanning (download cradles, encoded-command flags, PE-in-decoded-content,
  UPX, JavaScript eval chains).

Decoder and artifact-graph correctness:

- Require raw Deflate input to be exactly one complete DEFLATE stream
  (reject trailing `unused_data`), so ordinary text whose first bytes form a
  coincidental stream is no longer reported as a decode.
- Stop feeding analyzer-generated metadata artifacts (summary/metadata JSON)
  back through decoders and analyzers; they remain in the graph and still
  contribute to IOC extraction.
- Reserve analyzer summary names so an extracted file with the same
  sanitized name is deterministically renamed instead of shadowing the
  summary artifact.

Engine coverage, isolation, and response workflow:

- Add ASCII85, Base58, Base91, raw Deflate, PowerShell EncodedCommand,
  JavaScript escape, and optional Brotli/Zstandard decoders.
- Add bounded RFC/MIME, OOXML, script, Windows LNK, optional 7z/RAR/ISO/CAB,
  deeper PE/ELF, and expanded image/audio/video steganography analyzers.
- Version the Windows/Debian workbench protocol; route analysis, manual
  decoders, and Deep Scan through it with capability checks, progress,
  cancellation, and real timeouts.
- Add command-based VM/provenance assurance adapters and optional local
  Authenticode verification with strict hash-bound attestation validation.
- Run manifest plugins out of process by default with time, memory, input,
  output, offline-network, and configuration-disclosure controls.
- Add deterministic recursive Deep Scan and a recoverable, hash-addressed,
  copy-by-default quarantine with verified restoration.
- Add a 20-case decoder/analyzer calibration corpus with precision, recall,
  F1, specificity, accuracy, and per-component quality gates.
- Expose Deep Scan in the native Windows workbench and add CLI commands for
  scanning, quarantine listing/restoration, and calibration.
- Install the format extra in the supported Windows/WSL setup and make
  `--doctor` report optional-format readiness, missing modules, and recovery
  guidance; manual optional decoders now fail with an actionable message.
  Restore 7z extraction for the current py7zr API and correct ISO member-path
  resolution.

Integrated workbench interface redesign:

- Replace the oversized stock application chrome with a compact live header and
  status bar modeled on the Titan forensic-workbench reference.
- Rebalance the shell into dense navigation, investigation/results, and decoder
  columns; replace large quick-action buttons with compact selectable rows.
- Make navigation, center content, status cards, decoder lists, results, and
  details independently scrollable, with an automatic compact layout for narrow
  Codespaces terminals.
- Add `titan-ui` as a shorter launch alias while retaining
  `titan-workbench-ui` for backwards compatibility.

Integrated Textual workbench audit fixes:

- Await all dynamic widget removal/mount operations so analysis, decoder, report,
  and navigation refreshes cannot raise `DuplicateIds` under Textual 1.0.
- Treat overlong pasted text and hex as evidence instead of invalid filesystem
  paths; bound file reads before allocation using Titan's configured input cap.
- Save directory-queue reports with deterministic path/content identities and
  atomic replacement, preventing duplicate basenames from overwriting evidence.
- Escape evidence-derived Rich/Textual markup, reject non-object report JSON,
  tolerate malformed nested report values, avoid silent decoded-output
  replacement, and make resource metrics portable to Windows and macOS.
- Install the Textual extra in CI, add focused regressions, document the
  integrated workbench, and synchronize Textual into the committed SBOM.

Local AI Analyst (Milestone 8):

- New `titan-analyst` command (`titan_decoder/analyst/`): grounded Q&A
  over completed Titan reports. An immutable evidence ledger assigns
  stable, citable IDs to nodes, signals, detections, IOCs, ATT&CK
  techniques, risk facts, and Phase 5 correlation results (report-ordinal
  scoping prevents ID collisions across multiple loaded reports;
  content-hashed IOC IDs stay shared).
- Deterministic question planner routes the milestone example questions
  (risk explanation, PowerShell stages, decode chain, IOC→detection,
  MITRE techniques, summary, cross-case comparison, next steps) and
  selects a bounded evidence subset — the model never chooses its own
  evidence.
- Citation enforcement: every factual bullet must cite real ledger
  entries; invalid citations or uncited bullets reject the model answer.
  Backend errors and rejections fall back to the deterministic answer, so
  model failure never removes analyst output. Versioned response contract
  (`local-ai-analyst-response-v1.0`) with `fallback_used` and
  `validation_errors`.
- One tested backend: OpenAI-compatible local HTTP endpoints (llama.cpp
  server et al.), loopback-only by default (`--allow-remote-endpoint` is
  an explicit, warned opt-in), bounded timeout/tokens/response size,
  temperature 0. The deterministic no-model backend is the default — the
  AI is optional and off unless explicitly enabled.
- Prompt-injection containment for untrusted report content is structural
  (no tools, no network, citation-validated text output) and covered by a
  regression test.

Analyst Workbench (Milestone 7):

- New `titan-workbench` terminal application
  (`titan_decoder/workbench/`) for exploring completed Titan JSON reports
  — read-only over the deterministic engine's output, stdlib-only,
  offline-first. The interface decision (terminal app over local web or
  desktop) is documented in `docs/ANALYST_WORKBENCH.md`.
- Report library (single file or directory, bad files skipped non-fatally),
  report overview, filterable decode-tree explorer, and an interactive
  graph viewer with per-node drill-down (parent/children lineage, hashes,
  entropy, scores) and JSON/DOT/Mermaid export via the core graph
  exporter.
- IOC, detection (with ATT&CK IDs), timeline, and DFIR evidence browsers,
  a correlation view (relationships, attribution hints, campaigns), and
  ranked cross-report search over every scalar field with JSON-path
  locations.
- Persistent investigation workspaces (`analyst-workspace-v1.0`, JSON
  Schema in `schemas/`): per-report tags, notes, and case status plus
  workspace notes; tolerant loading of newer schema fields; workspaces
  store report paths and annotations only.
- Exports: IOC CSV and timeline CSV across loaded reports, active-report
  graph, and a portable investigation ZIP bundle
  (`analyst-bundle-v1.0`: workspace + manifest + report copies).

Interactive console upgrade:

- The `titan` command now opens a dashboard-style console
  (`titan_decoder/ui/`): session/system status panels (profile, network
  mode, decoder and plugin counts, correlation database state), analysis
  progress presentation, a concise analysis summary box with elapsed time,
  a default report-save location (`~/.titan_decoder/reports/`), a
  read-only Plugin SDK manager view (manifest and single-file plugins with
  load errors, over the same directory set the engine searches), a saved-
  reports browser, and expanded settings. Still stdlib-only, line-based
  numeric navigation, and a pure presentation layer over the engine.
- `EnhancedInteractiveApp` subclasses the existing `InteractiveApp`, which
  remains unchanged (and remains the tested core); plugin status on the
  dashboard is cached per session so menu redraws never re-execute plugin
  modules.

Plugin SDK v1 (Milestone 6):

- Four plugin SDKs behind the stable `titan_decoder.plugins.api` surface:
  `DecoderPlugin`, `AnalyzerPlugin`, `DetectionPlugin`, and `ReportPlugin`,
  with typed results (`DecodeResult`, `AnalysisArtifact`,
  `DetectionFinding`, `ReportSection`) and an optional `PluginContext`
  carrying the offline stance and resource bounds. Typed decode/analyze
  results unpack like the legacy tuples, so the engine consumes both plugin
  styles identically.
- Manifest plugins: a directory with `titan-plugin.json` (JSON Schema in
  `schemas/titan-plugin-manifest-v1.0.schema.json`) declaring identity,
  SemVer versions, entry point, capabilities, permissions (policy metadata,
  not a sandbox), and dependencies. Single-file plugins (API 1.0) keep
  loading exactly as before; `PLUGIN_API_VERSION` bumps to `1.1`
  (additive).
- Semantic version engine with correct SemVer 2.0.0 pre-release precedence
  (`1.0.0-alpha < 1.0.0`) and dependency requirements (`*`, `^`, `~`,
  comparator lists, exact). Manifest plugins load in deterministic
  dependency order.
- Pipeline integration: detection plugins run in the detection stage after
  rule engines and before risk scoring (findings carry
  `source: {"type": "plugin"}` and feed the risk assessment); report
  plugins contribute JSON-serializable sections embedded under
  `plugin_report_sections` and rendered into Markdown/HTML case reports.
  Bounded output: 200 findings / 20 sections per plugin; a failing plugin
  is skipped with a warning and can never abort an analysis.
- Guardrails: the `TITAN-` rule prefix is reserved (plugins cannot
  impersonate built-in detections), rule IDs must be declared and unique
  across plugins, undeclared findings are dropped, and duplicate plugin IDs
  are rejected.
- Deep validation (`--plugin-validate`): manifest contract, API
  compatibility, entry point, capability match, constructor, plus a bounded
  runtime probe checking return types, output limits, artifact names,
  declared rule IDs, and execution time. `--plugin-list` prints discovered
  plugins including per-plugin load errors; `--plugin-dir` adds search
  directories (repeatable).
- Example plugins (one per capability) in `examples/plugins/`, a complete
  developer guide in `docs/PLUGIN_API.md`, and SDK unit plus
  engine/CLI integration tests.

Evidence correlation (Milestone 5 completion):

- Cross-case persistence (correlation database schema v2): payload
  fingerprints and timeline events are stored alongside indicator records,
  so shared-payload and timeline correlation now operate across every
  recorded case without needing in-process `prior_reports`. Timeline
  events are capped at a deterministic 2,000 per analysis; v1 databases
  upgrade in place on open.
- Cross-case search: `--correlation-search [TYPE:]VALUE` (repeatable,
  standalone mode — no input file) queries the correlation IOC database
  and returns matching analyses with stored evidence references
  (`correlation-search-v1.0`). Also available as
  `titan_decoder.correlation.service.search_cases`.
- Deprecated the legacy `core/correlation.py` `CorrelationStore`
  (config key `enable_correlation`) in favor of the Phase 5 correlation
  database; using it now prints a deprecation warning.
- Roadmap updated: evidence correlation moved to Shipped; Plugin SDK v1
  and Analyst Workbench listed as next work.

Evidence correlation (Phase 5 milestone complete):

- Campaign clustering (`titan_decoder/correlation/campaigns.py`): connected
  components over the deterministic relationship graph, with stable
  campaign IDs and per-campaign confidence
  (`campaign-clusters-v1.0`).
- Cross-case timeline correlation
  (`titan_decoder/correlation/timeline_correlation.py`): links events from
  different analyses within a configurable window; shared observable
  metadata forms strong links, matching event kinds weaker ones. `None`
  and nested metadata values are never compared
  (`timeline-correlation-v1.0`).
- Infrastructure reuse detection
  (`titan_decoder/correlation/infrastructure.py`): domains, URLs, public
  IPs, certificates, JA3/JA4, ASNs, nameservers, and WHOIS emails shared
  across recorded analyses; private IP ranges excluded by design
  (`infrastructure-reuse-v1.0`).
- Shared payload detection
  (`titan_decoder/correlation/payload_similarity.py`): per-report
  fingerprints from node content hashes and decode chains, pairwise
  scoring with an exact-hash-dominant weighting
  (`shared-payload-v1.0`).
- Evidence-backed attribution hints
  (`titan_decoder/correlation/attribution.py`): per-pair hints combining
  infrastructure, payload, and ATT&CK/tag overlap. Hints are explicitly
  investigative leads and never actor identity claims
  (`attribution-hints-v1.0`).
- Report adapters (`titan_decoder/correlation/adapters.py`) translate
  engine reports (meta/nodes/iocs/detections/threat_intelligence/evidence)
  into correlation records: root hash from the root node's sha256, decode
  chain from `decoder_used`/`method`, ATT&CK IDs from detections and
  threat-intelligence techniques, timeline events from DFIR evidence
  events.
- Service orchestration
  (`titan_decoder/correlation/service.py::analyze_milestone5`) runs the
  full suite against the local SQLite database and returns the combined
  `milestone-5-report-v1.0` result (schema in
  `schemas/milestone-5-report-v1.0.schema.json`), including the analyst
  view (`titan_decoder/correlation/views.py`; JSON/Markdown/HTML).
- CLI integration: `--correlation-db`, `--correlation-out`,
  `--correlation-min-score`, `--correlation-no-record`, `--campaign-out`,
  `--campaign-min-score`, `--timeline-correlation-out`,
  `--timeline-window-seconds`, `--infrastructure-reuse-out`,
  `--shared-payload-out`, `--shared-payload-min-score`,
  `--attribution-hints-out`, `--analyst-correlation-out`,
  `--analyst-correlation-format`. Requesting any of them embeds the
  correlation sections in the main JSON report.

Rule packs:

- Harden rule packs with enforced validation, duplicate-ID checks, and
  limits (completing the roadmap item). `validate_rule_def` /
  `validate_rule_pack` (`titan_decoder/core/rule_packs.py`) check ids
  (required, ≤64 chars, `TITAN-` prefix reserved for built-ins so packs
  cannot impersonate them), rule types, regex patterns (non-empty, ≤2048
  chars, must compile), flags (IGNORECASE/MULTILINE/DOTALL only), severity
  (low/medium/high/critical), `ioc_types` (non-empty, ≤16, `min_each` in
  [1, 10000]), and `attack_ids` (≤16, `T1234`/`T1234.001` form). Packs are
  capped at 200 rules; beyond that the whole pack is rejected, since each
  `content_regex` evaluation has bounded-but-real cost.
- Enforcement at load: the engine skips invalid rules and duplicate ids
  (within a pack, across packs, and against built-ins — first definition
  wins) with a logged warning instead of loading them as silent no-op
  rules, and records per-pack `rules_loaded`/`rules_skipped` counts in
  `meta.rule_packs`.
- `--rules-validate` is now a deep, strict gate: it runs the full per-rule
  validation and duplicate-ID check, reports every problem per rule in its
  JSON output, and exits non-zero on any error (previously it only checked
  that the file parsed).
- Fixture packs (valid, duplicate-ID, invalid-rules) in
  `tests/fixtures/rule_packs/` back a new validation test suite
  (`tests/test_rule_pack_validation.py`), including engine load-time
  behavior and CLI exit codes.

Threat Intelligence Engine:

- Resolve the six catalog techniques that had no built-in producer. Four gain
  evidence-backed behavior rules: T1003.001 LSASS Memory (`sekurlsa`,
  `lsass.exe`/`lsass.dmp`, `procdump … lsass`, `comsvcs … MiniDump`),
  T1059.007 JavaScript (WSH markers only — `jscript`, `new ActiveXObject(`,
  `.jse` — so web-"JavaScript" prose cannot fire), T1486 Data Encrypted for
  Impact (ransom-note language only — `ransom`, `decryptor`,
  "decrypt/restore/recover your files" — never the bare word "encrypted"),
  and T1566.001 Spearphishing Attachment (decoded MIME attachment header
  naming an executable/script/container payload extension; `.pdf`/`.docx`
  do not match). The remaining two — T1071 Application Layer Protocol
  (not deterministically evidenceable from content) and T1204 User Execution
  (parent-level form for rule packs; built-ins attribute T1204.002) — are
  explicitly designated rule-pack-only. New catalog tests enforce both
  directions: no catalog technique may lack a producer unless deliberately
  listed rule-pack-only, and listed entries must genuinely lack one.
- Calibration corpus: one changed case (`credential-theft-lsass` now also
  yields T1003.001, corroborating the parent; confidence 0.72 → 0.74), plus
  five new cases — four malicious (LSASS dump, JScript ActiveXObject
  dropper, ransom note, spearphishing attachment) and one benign guard
  (encryption-at-rest prose, a `.pdf` attachment header, and web-JavaScript
  wording must stay completely clean).

- Add a deterministic Threat Intelligence Engine (`titan_decoder/threat_intel/`)
  that maps decoded evidence to a bundled offline MITRE ATT&CK subset,
  identifies suspicious LOLBin usage (13 built-in rules), and emits behavioral
  malware tags (downloader-like, script-stager-like, credential-theft-like,
  ransomware-impact-like, host-discovery-like, living-off-the-land-chain) —
  explicitly behavior descriptions, not malware-family attribution. Findings
  carry per-item confidence, supporting evidence with node IDs, and
  deterministic node → technique/LOLBin/tag relationships; the overall
  assessment is versioned (`1.0`) with its own catalog version.
- Wire the threat stage into the CLI pipeline after the Intelligence stage,
  reusing the same canonical IOC summary (report + ingested evidence) so cited
  indicators stay consistent across outputs. The result is attached to every
  report as `threat_intelligence`.
- Render a Threat Intelligence section (ATT&CK table, LOLBins, behavioral
  tags) in Markdown and HTML case reports, and annotate graph exports:
  graph-level threat metadata in JSON, plus per-node ATT&CK/LOLBin/tag labels
  in JSON, DOT, and Mermaid outputs.
- Ship the ATT&CK catalog subset as package data (wheel and sdist) and
  document the subsystem in `docs/THREAT_INTELLIGENCE.md`.
- Expand the bundled ATT&CK catalog subset from 23 to 48 techniques
  (catalog version `enterprise-2026.1-titan-subset-r3`), covering discovery,
  persistence, impact, defense-evasion, credential-access, and initial-access
  techniques relevant to payload analysis, and pair the new entries with
  producers: 14 new behavior rules (masquerading double-extensions, Unix
  shell / Python inline execution, file deletion, registry modification,
  service install/stop, recovery inhibition, network/user/process/account
  discovery, credentials-in-files, cron) and 10 new LOLBin rules (MSBuild,
  CMSTP, Odbcconf, Regsvcs, Regasm, Forfiles, Pcalua, hh.exe, at.exe,
  crontab — the last three require unambiguous forms so everyday words like
  "at" and "hh:mm" cannot fire them). Shadow-copy deletion evidence now
  correctly maps to T1490 Inhibit System Recovery instead of T1486, and
  `cipher /w:` moved to T1070.004 File Deletion. New catalog-integrity tests
  assert IDs are unique and well-formed and that every technique referenced
  by behavior rules, LOLBin rules, or detection `attack_ids` exists in the
  catalog.
- Wire `attack_ids` onto every built-in detection rule (TITAN-001…007) and
  expose them on triggered detections, so fired rules corroborate ATT&CK
  technique findings in the Threat Intelligence assessment. Rule packs can
  declare the same optional `attack_ids` field per rule. The bundled catalog
  gains T1059, T1218, and T1204.002 (catalog version
  `enterprise-2026.1-titan-subset-r2`), and a test asserts every rule-declared
  technique ID exists in the catalog.
- Precision hardening: indicators alone no longer become behavioral findings.
  The T1105 network-transfer behavior rule requires a retrieval verb instead
  of firing on any `http(s)://` URL; the `cmd` LOLBin rule requires the
  literal `cmd.exe` form or an invocation term (`/c `, `/k `) in the same
  node, so the everyday word "cmd" in prose cannot fire (new
  `bare_requires_term` option on `LOLBinRule`); and the `downloader-like`
  malware tag requires observed retrieval behavior — URL IOCs only
  corroborate (0.78 → 0.84), they never create the tag on their own. A benign
  meeting-notes document containing a URL and the word "cmd" previously
  scored 0.8 overall confidence with T1059.003, T1105, a `cmd.exe` LOLBin,
  and a `downloader-like` tag; it now produces a completely clean assessment.
- Recalibrate overall assessment confidence: anchored to the strongest
  individual finding with bounded corroboration/diversity increments,
  replacing an additive floor that saturated near the 0.98 cap on modest
  evidence. The value can no longer substantially exceed what any single
  finding supports, and a single weak finding stays below 0.5.
- Add a deterministic calibration corpus
  (`tests/fixtures/threat_intel/calibration-v1.json`) and CI gate
  (`tests/test_threat_calibration.py`), mirroring the Intelligence Layer's.
  Benign cases (prose with URLs, everyday words overlapping rule vocabulary)
  must produce a completely clean assessment; malicious cases pin exact
  technique/LOLBin/tag output and confidence, so precision regressions and
  unreviewed confidence drift fail CI.

Detection quality:

- Harden the LOLBin rule (TITAN-003): it now requires a LOLBin name to co-occur
  with a strong abuse/execution-context token (encoded command, hidden window,
  download cradle, script-COM registration, `/c`, etc.) instead of firing on a
  bare mention. A benign document that merely names "PowerShell" or "cmd.exe" no
  longer false-positives. Adds a benign "tool mention" corpus sample that would
  have tripped the old rule, plus direct unit tests; all rules stay
  precision/recall 1.000 on the corpus.

Docs:

- README accuracy pass against the actual engine: corrected the "21 core
  modules" wording (that number is the decoder count, not the module count),
  noted case reports render Markdown **and** HTML, added the `decoders/cfb.py`
  and `decoders/pdf.py` structural parsers to the architecture tree, and
  labelled the STIX export as a minimal 2.1 bundle to match the implementation.
  Verified every CLI flag, the Python API snippet, and the smoke-test command in
  the README against the code.

- Document the interactive `titan` UI in the day-to-day guide
  (`docs/USAGE.md`) — a dedicated "Interactive mode" section covering
  auto-detect vs. single-decoder, saving output, and the aggressive toggle —
  and note both entry points (`titan` / `titan-decoder`). Add the interactive
  UI to the README feature list and the announcement quick-start.

Tests:

- Make `test_utf16_decoder.py` deterministic. The random-binary
  no-hallucination checks drew unseeded `os.urandom` blobs and asserted zero
  UTF-16 false positives, so an unlucky draw could flake CI (observed once on
  the 3.11 job). Seeded RNGs give the same coverage with reproducible results.

Interactive UI:

- Add a menu-driven interactive console, launched with the new `titan` command
  (or `titan-decoder --interactive` / `-i`). Instead of memorizing CLI flags,
  users get a menu to auto-detect & fully decode a payload, or pick a specific
  decoder (Base64, Hex, XOR, Gzip, ROT13, URL, UTF-16, …) and feed it typed
  text, a hex string, or a file. It's a thin, stdlib-only presentation layer
  over the same engine and decoders the `titan-decoder` CLI drives — no analysis
  logic is duplicated. Results render as decoded text or a hexdump, and
  auto-detect shows the recursive decode tree plus extracted IOCs. New
  `titan_decoder/interactive.py` module with unit tests that drive the loop via
  injected I/O (no real TTY required).
- Interactive UI can now save results to disk: after a single-decoder decode it
  offers to write the raw decoded bytes to a file, and after an auto-detect run
  it offers to save the full JSON report. Blank input skips (the default), and
  missing parent directories are created.
- Interactive UI gains an **aggressive auto-detect** toggle (Options → [3]). When
  on, an auto-detect run enables the opt-in decoders
  (Base32/UUencode/Quoted-Printable/ASN.1), searches deeper, and lowers the
  keep-threshold so weaker/shorter decodes survive — useful for hands-on testing.
  It is strictly session-scoped: the settings are applied per-run to the engine
  config and fully restored when toggled off, so the core-engine defaults used by
  `titan-decoder`, the test suite, and real analysis runs are never changed.

Packaging / install:

- Document installing without cloning:
  `pip install "git+https://github.com/pragmaconflux/titan1.git"` (and a `pipx`
  variant). README now covers the Python 3.10+ requirement and the
  Debian/Ubuntu `externally-managed-environment` (PEP 668) venv workaround.
- Add an **optional** PyPI publish job to the release workflow, gated behind the
  `PUBLISH_TO_PYPI` repository variable and PyPI Trusted Publishing (OIDC, no
  stored token). It is disabled by default and cannot affect existing releases
  until a maintainer opts in.

Reproducible builds:

- Make the sdist byte-reproducible. `bdist_wheel` honors `SOURCE_DATE_EPOCH`
  but setuptools stores sdist tar members with filesystem mtimes, so every
  build differed. New `tools/repack_sdist.py` normalizes the tarball (member
  mtimes to `SOURCE_DATE_EPOCH`, ownership/modes, member order, gzip
  timestamp) with a content-preservation self-check, and the release workflow
  runs it after `python -m build`.

Audit cleanup (post-roadmap):

- Tolerate trailing bytes after a complete gzip/bz2/zlib/xz stream: zero
  padding or appended data (both common in real-world samples and carved
  artifacts) previously made the *entire* decode fail, discarding fully
  decoded content and its IOCs. A truncated or invalid first stream still
  fails, a partial trailing member never leaks partial output, and the
  decompression-bomb output cap is unchanged.
- Make the PDF `LZWDecode` output cap a hard stop and bound it by the
  document's configured `max_output`: the previous `break` only exited the
  inner code loop, so a crafted stream could keep growing output past the cap.
- Remove dead pruning-policy config (`quality_decay_threshold`,
  `max_consecutive_low_scores`, `min_content_similarity`,
  `prune_empty_decodes`, `prune_identical_content`): the keys were stored and
  echoed into `run_manifest.effective_config` but no logic ever read them, so
  they promised tuning knobs that did nothing. Unknown keys in existing user
  configs are still accepted and simply ignored, as before.
- Remove an always-false prune check in the analyzer extraction path (decoded
  content is never score-pruned by definition) and other dead code
  (`PruningEngine.get_pruning_stats`, unused `ResourceManager` timeout
  attributes).
- Batch mode now warns that `--evidence-timeline-out` is ignored instead of
  ignoring it silently.

Decoder correctness (Milestone 1):

- Replace the OLE signature-window carver with a real Compound File Binary
  (CFB/OLE2) parser: it walks the header, FAT/DIFAT, directory tree, and
  mini-stream, enumerates streams by their real directory path (e.g.
  `Macros/VBA/Module1`), and decompresses VBA source from module streams via
  the MS-OVBA compressed-container format. Extracted artifacts are named after
  real stream paths and the old window-carving false positives (signature bytes
  in random data) are gone.
- Make the PDF decoder object-graph aware: it parses indirect objects,
  decompresses object streams (`/Type /ObjStm`) so their packed objects become
  visible, resolves indirect references, and applies `/Filter` chains
  (FlateDecode, ASCIIHexDecode, ASCII85Decode, LZWDecode, with predictors). It
  extracts `/JS`, `/OpenAction`, and `/EmbeddedFile` by reference rather than by
  regex — resolving a stream referenced only as `5 0 R` and recovering objects
  packed inside an object stream.
- Extend the XOR decoder to repeating keys (lengths 2–8) via per-column
  frequency analysis, with sampled scoring that raises the size cap to 1 MB
  while keeping cost bounded (single full decode only on acceptance) and an
  entropy gate that skips near-random input.

Detection quality (Milestone 1/4):

- Add `tools/eval_detections.py` measuring per-rule precision/recall over a
  synthetic labeled corpus (`tools/corpus_samples.py`); the risk-score weights
  in `risk_scoring.py` cite that measurement. Numbers committed in
  `docs/detection_metrics.json` and `docs/DETECTION_QUALITY.md`, with
  per-release history in `docs/detection_quality_history.jsonl`. Fixed
  TITAN-001 to catch collapsed `RecursiveBase64` nesting.

Structure & verification (Milestone 2):

- Decompose `cli.main()` from a ~900-line function into a thin dispatcher plus
  independently-testable stages (load_input, run_analysis, attach_evidence,
  run_detections, write_outputs, …); CLI behaviors are asserted at the stage
  level.
- Add a fuzz harness (`fuzz/`) over every decoder and analyzer enforcing the
  never-raise / bounded-output / bounded-time invariants, with a checked-in seed
  corpus, Hypothesis property tests, and a bounded CI job.
- Wire mypy (non-strict baseline with a ratchet list), a pytest-cov 70% floor,
  and Python 3.13 into CI.
- Defend the rule-pack ReDoS surface: pack `content_regex` patterns run under
  linear-time RE2 when available, else in a killable subprocess with a hard
  timeout — a catastrophic `(a+)+$` pattern is bounded instead of hanging.

Contract, reproducibility & performance (Milestone 3):

- Bump the report schema to 1.2 with first-class per-node provenance (origin,
  producing decoder/analyzer, parent hash, confidence, artifact name, reason).
  CI validates every emitted report against `docs/report.schema.json`, the
  schema and code version are locked in step, and a compatibility policy is
  documented (`docs/SCHEMA_COMPATIBILITY.md`).
- Add a golden differential corpus (`tools/golden.py`) so any change in analysis
  output surfaces as a reviewable diff, plus reproducibility assertions
  (byte-identical normalized reports across runs).
- Add a performance regression gate (`tools/bench.py`) against a committed
  baseline: node counts checked exactly, wall-clock hardware-normalized.

Beyond A+ (Milestone 4):

- Publish a threat model (`docs/THREAT_MODEL.md`) with an executable red-team
  suite and property tests over the safety-critical resource bounds.
- Add a versioned plugin API contract (`titan_decoder.plugins.api`,
  `docs/PLUGIN_API.md`) with load-time compatibility checking.
- Add supply-chain integrity: a deterministic CycloneDX SBOM, reproducible-build
  guidance, and a signing release workflow (`docs/SUPPLY_CHAIN.md`).

CLI:

- Restore Ctrl+C: a signal handler set a flag nothing ever read, so SIGINT
  could not stop a running analysis (and the `except KeyboardInterrupt`
  handlers were unreachable). Interrupts now abort with exit code 130.
- Fix batch mode printing literal `\n` instead of newlines.
- Batch mode now processes files in sorted (deterministic) order, reuses one
  engine across files, warns about single-file-only options it ignores, and
  propagates its exit code under `python -m` invocation.
- Fix `--perf-profile` always reporting 0 nodes processed / 0 throughput.
- Validate `--evidence` paths before the analysis runs instead of after.
- `--list-decoders --list-analyzers` together now lists both.

Correctness:

- Detections, risk scoring, enrichment, and IOC/case exports now extract IOCs
  from every node preview (matching the engine report) instead of only
  Text-classified nodes, which silently dropped C2 indicators embedded in
  binary content from all downstream tooling.
- Correlation no longer matches every run against itself (the current run was
  recorded before correlating), and a user-configured `correlation_db_path`
  no longer silently disables correlation (string path crashed on `.parent`).
  The correlation DB now enforces `UNIQUE(type, value)` and stops re-inserting
  duplicate indicator rows on every run.
- STIX/MISP exports label hashes by digest length (MD5/SHA-1/SHA-256/…)
  instead of exporting every hash as SHA-256.
- IMSI detection worked never: the IMEI and IMSI regexes were identical and
  IMSI candidates were then filtered against the IMEI list. IMEIs are now
  Luhn-validated; 15-digit non-Luhn numbers are reported as IMSI candidates.
- `top_links` ranked confidence lexicographically ("medium" > "high"); it now
  compares numerically.
- Fix the `<?xml` structure-scoring pattern (matched bare "xml" anywhere) and
  anchor the two-byte MZ/BZ magics to the start of data.
- Evidence event IDs are now unique and deterministic (monotonic counter);
  wall-clock IDs collided within a microsecond and differed across runs.
- Parse millisecond epoch timestamps in evidence logs (previously interpreted
  as seconds, producing year-56000 dates).
- Unicode-escape decoder handles surrogate pairs (`😀`); previously
  one astral escape made the entire decode fail.
- PDF stream extraction handles nested dictionaries (e.g. `/DecodeParms
  <<...>>`), which the old `<<([^>]*)>>` regex could never match.
- Stop IOC extraction from reporting dotted .NET/scripting member access in
  download-cradle payloads (e.g. `Net.WebClient`, `Net.HttpWebRequest`) as
  bogus domains. Their trailing labels are verified non-TLDs and added to a
  denylist, so real C2 domains are unaffected.

Removed:

- Parallel archive extraction. `tarfile` is not thread-safe (concurrent reads
  can silently corrupt extracted content), the in-memory source gains nothing
  from threads, and completion-order results made reports nondeterministic.
  The `enable_parallel_extraction`/`max_parallel_workers` config keys are
  gone; extraction is sequential and deterministic.
- Phantom VirusTotal integration: the API-key config and "virustotal" provider
  listing implied lookups that no code performed.
- Dead config flags that nothing read: `enable_entropy_analysis`,
  `enable_script_analysis`, `enable_shellcode_detection`,
  `enable_string_extraction`, `enable_xor_keyfinding`,
  `enable_polymorphic_detection`, `enable_yara_generation`,
  `enable_html_reports`, `enable_pii_redaction` (log redaction is controlled
  by `--no-redaction`), and `vault_prune_days` (use `--vault-prune-days`).

Behavior:

- WHOIS enrichment honors its cooldown by waiting between queries instead of
  permanently skipping every indicator after the first with
  `{"_rate_limited": true}`.
- `meta.enrichment_providers` now lists providers that actually initialized
  (library present, DB/rules loaded), not what the config requested.
- A malformed `~/.titan_decoder/config.json` now logs a warning instead of
  silently reverting every setting to defaults.

Packaging / CI:

- Project metadata migrated from `setup.py` to the `[project]` table in
  `pyproject.toml`; ruff lint added to CI.

## 2.0.2 — Engine reliability fixes (2026-07-02)

Reliability (engine no longer fails silently or nondeterministically):

- Fix silent no-op analysis off the main thread and on Windows: SIGALRM-based
  per-operation timeouts crashed where SIGALRM is unavailable, and the engine
  swallowed the per-decoder error — every decoder/analyzer was skipped with no
  warning. Timeouts now degrade to unguarded execution (the run-level
  wall-clock deadline and memory bounds still apply).
- Stop text-transform decoders (URL, HTML-entity, unicode-escape) from
  hijacking binary decode chains: decoding with `errors="ignore"` silently
  deleted non-UTF-8 bytes, reported the mangled output as a successful decode,
  and could outscore the correct decoder (e.g. Gzip), killing the chain and
  losing every IOC in ~6% of layered payloads. These decoders now require
  valid UTF-8 input.
- Reset smart-detection decoder state between `run_analysis()` calls, so
  results on a reused engine no longer depend on what was analyzed earlier.
- Register off-by-default decoders (uuencode/asn1/quoted-printable/base32)
  when enabled via config — previously the config flags had no effect.

Correctness:

- Validate the full RFC 1950 zlib header (CINFO, FCHECK) instead of one
  nibble, cutting false decode attempts on random binary data from ~6.5% to
  ~0.07%.
- Accept all valid unpadded base32 lengths (mod 8 in {0, 2, 4, 5, 7}).
- Fix the UU decoder's stripped-whitespace retry slicing one character too
  many (now matches CPython's reference formula).
- Label PE machine type 0x01C4 as ARM Thumb-2 (ARMNT), not ARM64.
- Restrict hex detection to strict hex digits (`int(x, 16)` also accepted
  `0x`/sign/underscore forms that `unhexlify` rejects).
- Align config decoder flags with the real decoder set (add
  `base64url`/`pem`/`utf16`; remove nonexistent `base85`) and fix
  `QuotedPrintableDecoder.can_decode` to return a bool.

Testing:

- 9 new regression tests covering each fix (199 total).
- Verified with 600 hard-mode stress iterations (100% IOC recovery, was ~94%)
  plus an adversarial harness: fuzzing, decompression bombs, nested-archive
  fan-out, flood inputs, and determinism checks — all bounded and crash-free.

## 2.0.1 — Hardening & correctness (2026-06-30)

Security / DoS resistance (untrusted-input hardening):

- Bound decompressor output for Gzip/Bz2/LZMA/Zlib to defeat decompression
  bombs (incremental, multi-stream-aware, capped by `max_data_size`).
- Bound PDF FlateDecode output the same way, so a malicious object stream
  can't exhaust memory.
- Bound OLE decoder output and fix an O(n^2) VBA-string scan that could hang
  on crafted documents (per-signature match cap + output budget).
- Fix O(n^2) blow-ups in the URL and HTML-entity decoders (single-pass
  rewrites) that let small inputs burn large amounts of CPU.
- Harden evidence ingestion: O(n) indicator merge (was O(n^2)), a bounded CSV
  field-size limit, and per-row skipping so a malformed row/field can't abort
  the whole run.
- Degrade gracefully on corrupt browser-history SQLite files instead of
  crashing the evidence run.
- Make `psutil` truly optional: `--perf-profile` now runs (timing + cProfile)
  and reports memory/CPU as `0.0` when psutil isn't installed, instead of
  crashing with `ModuleNotFoundError`.
- Document the rule-pack `content_regex` ReDoS trust boundary: patterns run
  with Python's `re` (no timeout); only load packs you trust.

Correctness:

- Fix ELF metadata parsing for 64-bit and big-endian binaries.
- Fix PE metadata parsing (broken optional-header struct format) and bound the
  image-base read.
- Detect GNU-format tar archives (`ustar` magic at offset 257).
- Reject invalid IPv4 addresses and correct public/private classification via
  `ipaddress`.
- Stop hex blobs being mis-reported as hash IOCs (exact-length matching).
- Stop ROT13 from mangling plaintext and polluting IOCs (English-likeness gate).
- Reduce IOC/forensics false positives from filenames and encoded layers.
- Reimplement the UU decoder without the deprecated stdlib `uu` module, and fix
  the UU/QuotedPrintable decoder return contract on the failure path.
- Fix IOC export: STIX value quote-escaping and MISP duplicate-IP dedup;
  timezone-aware timestamps.

Maintenance:

- Remove dead path-pruning code and unused `titan_decoder.core` modules.
- Add regression tests across decoders, analyzers, evidence/endpoint parsers,
  IOC export, decompression-bomb defenses, and the profiler (124+ tests).

## 2.0.0

- Evidence ingestion layer (canonical events/indicators) with pivots/last-seen.
- Evidence links (reason codes + confidence) and evidence timeline export.
- Endpoint artifact parsing: PowerShell history and browser history SQLite.
- Deterministic enrichment caching (SQLite) with refresh control.
- CLI hardening: offline-first mode, clean outputs, doctor mode, vault.
