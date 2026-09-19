# Titan Depth-Hardening Program

Titan's major feature surface is intentionally paused while the shipped engine
is made deeper, more measurable, and harder to fool. New product modes and
headline subsystems can return later; bug fixes and security corrections remain
in scope throughout this program.

This program follows the project charter: offline first, decoder first,
evidence first, deterministic, bounded, transparent, and defensive.

## What "depth" means

Depth is not another feature name. It is stronger evidence that an existing
capability works across varied, malformed, adversarial, and operationally
realistic inputs.

1. **Detection content and calibration** — more native and YARA content, with
   measured positives, targeted benign near-misses, cross-rule interactions,
   and truthful precision/recall reporting.
2. **Corpus quality** — larger labeled corpora built from multiple generators,
   public-safe fixtures, format variants, and field-derived misses; synthetic
   design samples remain regression anchors, not field-accuracy claims.
3. **Decoder and parser correctness** — every advertised decoder/analyzer gets
   positive, clean-negative, malformed, truncated, oversized, recursive, and
   cross-format cases where applicable.
4. **Adversarial robustness** — fuzzing, decompression bombs, archive traversal,
   parser confusion, Unicode edge cases, plugin failures, report poisoning, and
   resource-exhaustion attempts fail closed.
5. **Determinism and provenance** — cross-platform golden reports, stable graph
   hashes, schema compatibility, canonical ordering, and parent/child evidence
   integrity are continuously verified.
6. **Code assurance** — raise the coverage floor in measured steps, remove mypy
   exemptions module by module, strengthen lint rules, and add property and
   mutation tests where ordinary examples are weak.
7. **Performance and resource bounds** — expand benchmark shapes and verify
   time, memory, node, output, queue, and concurrency limits without weakening
   forensic output.
8. **Operational security** — harden plugin isolation, service authentication,
   quarantine and restoration, WSL/native boundaries, update/release integrity,
   and safe handling of hostile filenames and evidence metadata.
9. **External trust** — complete the independent parser review, publish its
   scope and limitations, reproduce results on clean systems, and grow a real
   third-party corpus/plugin/user feedback loop.

## Ordered execution

### D1 — Detection-quality foundation

Current focused slice:

- derive the measured rule set from the live built-in registry;
- require every built-in rule to have multiple positives and targeted benign
  near-misses;
- include `TITAN-008` in published metrics;
- fail the evaluator on precision, recall, label, coverage, near-miss, or risk-
  separation regression;
- correct broad LOLBin and high-entropy false-positive boundaries.

Baseline gate: at least two positives and two targeted near-misses per built-in
rule. This is a floor, not the final content target.

### D2 — Detection-content scale

- Grow native and starter YARA content in small reviewed batches.
- Require each new rule to ship with multiple behavior variants, benign
  lookalikes, ATT&CK metadata, severity rationale, and graph-node coverage.
- Add multi-rule samples so interactions and risk stacking are measured.
- Expand toward hundreds of diverse labeled cases before making broad accuracy
  claims, then toward thousands using out-of-tree public or licensed corpora.
- Record misses and false positives by engine/rule version so content improves
  from evidence rather than count alone.

### D3 — Decoder/analyzer calibration parity

- Discover the live decoder/analyzer registry automatically, as D1 does for
  rules.
- Fail CI when an advertised component has no labeled calibration slice.
- Add positive, negative, malformed, truncation, size-bound, and nested-chain
  cases for every component.
- Separate format recognition accuracy from extraction correctness and output-
  hash determinism.
- Exercise every decoder through a **host carrier**, not only as a whole
  buffer. Whole-buffer fixtures cannot observe the engine's largest blind
  spot, and a corpus made only of them reported 1.0 precision and recall
  while a JS dropper carrying `base64(gzip(powershell -EncodedCommand ...))`
  produced no indicators at all.
- Run host-embedded cases through the **engine**, not the component in
  isolation, so decoder selection is in scope. Isolated evaluation hid a real
  conflict: an even-length hex string is also valid base64, both decoders
  claimed it, and Base64 won on decoder cost because neither entropy reduction
  nor printable *gain* separates a good decode from garbage when the input is
  already fully printable. Decoding is winner-takes-all, so the engine
  returned noise and the real payload was never produced. Scoring now
  penalizes decodes that destroy printable structure without producing
  anything recognizable.
- Track the miss list as a contract in both directions. A new miss is a
  regression; a fixed miss must shrink the recorded list. See
  `tests/test_host_embedded_corpus.py`.
- Measure `nested_chain` at engine level, not per component. The class reads
  zero for every component in the calibration matrix, and that is a category
  error rather than missing work: the evaluator runs one component in
  isolation, and `GzipDecoder.can_decode(base64(gzip(x)))` is False, so a
  nested case authored against a component would be scored as a negative
  recognition case and would measure nothing about chaining. Chaining is a
  property of recursion, decoder selection, and carving acting together, and
  is covered by `tests/test_nested_chain_corpus.py` (20 of 21 layered,
  host-carried, and mixed compression/transport chains unwind to the same
  innermost payload and surface its indicator).
- Require `size_bound` of every component that can amplify, derived from the
  live registry: exposing an output cap is what makes the class meaningful, so
  all nine amplifying decoders now carry a case and the gate fails if one
  loses it. The class is deliberately *not* required of one-to-one transforms
  like ROT13 and Base64, which cannot produce more output than their input
  warrants — demanding it there would manufacture fixtures that measure
  nothing, repeating the `nested_chain` category error.
- Let a size-bound case shrink the component's cap for its own duration.
  Exercising the shipped 50 MB defaults honestly would mean committing real
  decompression bombs and allocating 50 MB per case in CI; shrinking the cap
  reaches the same code path with a few hundred bytes. Only attributes the
  component already defines may be overridden, and the value is restored
  afterwards so a leaked override cannot alter later cases.
- Assert the property all three refusal shapes share. Some decoders decline at
  recognition, some fail the decode, and some truncate to the cap; all are
  correct, and none may exceed `expected_max_output_bytes`.
- Cover analyzers as well as decoders. They declare their ceiling through
  `max_total`/`max_total_size`, so a decoder-shaped cap lookup could not see
  them at all. Extending it exposed a real defect rather than a missing
  fixture: six of eleven cap-bearing analyzers overshot their declared bound,
  because summary records were spliced past the collector that enforces it.
- Enforce the bound itself, not merely the presence of a case. A `size_bound`
  case that emits more than it declares fails the gate even when it does not
  assert extraction, so cases guarded by optional modules still measure
  something.

### D4 — Continuous adversarial testing

- Keep the bounded pull-request fuzz gate for fast feedback.
- Add longer scheduled fuzz campaigns with retained minimized reproducers.
- Cover analyzers, archives, evidence parsers, plugin transport, server request
  parsing, report loading, and export paths—not decoders alone.
- Track iterations, unique paths/cases, crashes, timeouts, and bound violations
  over time.

### D5 — Code-assurance ratchet

- Increase the coverage floor from 70% in reviewable steps without excluding
  difficult security-critical code.
- **Complete.** The mypy exemption list is empty: every module in the package
  type-checks with no `ignore_errors`. Removed in order — evidence parsers,
  then `core.engine` with `core.graph_export` and `plugins` (the latter two
  already checked clean and were exempt for no remaining reason), then the two
  sqlite stores together since they shared one cause, then
  `core.analyzers.base` and `core.ioc_export`.
- Every fix was an annotation or an interface correction, never a suppression,
  and two were real defects rather than missing types: the engine called
  `analyzer.carve` on a base class that never declared it, and the TAR
  extractor called `.read()` on `extractfile()` results that are `None` for
  directories and symlinks.
- Keep the list empty with `tests/test_mypy_ratchet.py`, which fails if an
  exemption is reintroduced, if a cleaned module goes back on the list, or if
  anything in the package stops type-checking.
- Expand lint rules only with a clean migration and a permanent CI gate.
- Add property tests for ordering, hashing, deduplication, bounds, and schema
  round trips.

### D6 — Determinism, provenance, and compatibility

- Verify golden reports on Linux and Windows across supported Python versions.
- Add property checks for root commitments, lineage hashes, graph ordering,
  deduplication, and stable export identities.
- Test old report/workspace/plugin contracts against current readers.
- Publish explicit compatibility and migration policy for every versioned
  schema.

### D7 — Performance and operational hardening

- Expand benchmarks beyond ten cases to deep graphs, large directories,
  archives, media, executables, evidence correlation, and concurrent service
  workloads.
- Measure peak memory and output amplification in addition to normalized time.
- Harden authentication, rate/queue bounds, artifact storage, cancellation,
  recovery, plugin containment, and quarantine atomicity.
- Never advertise a bound the host cannot enforce. Per-operation timeouts rely
  on SIGALRM, which is POSIX-and-main-thread-only, so the desktop UI's
  analysis thread has none on any platform; memory measurement needs psutil or
  the POSIX `resource` module. Where enforcement is unavailable the run records
  `operation_timeout_unenforced` or `memory_bound_unenforced` rather than
  reporting a limit nothing checked.
- Supervised workers now provide the enforcement those limitations describe.
  `titan cli --file X --supervised` and `--deep-scan-supervised` run analysis
  in a spawned process under OS memory limits and a parent-held deadline with
  real kill authority, so a parser that never returns is terminated rather
  than merely noted. Termination yields an `indeterminate` status and no
  report; it is never a clean verdict.
- Exercise native Windows, WSL, Debian, and constrained-device workflows with
  repeatable smoke suites.

### D8 — Independent validation and trust

**D8 is an outreach task, not an engineering slice.** It is gated entirely on
finding an assessor independent of the implementation authors, and no amount
of internal work advances it. Treating it as a roadmap item creates a standing
"blocked" row that invites the appearance of progress where none is possible.
The engineering prerequisites are already done: `docs/proof/parser-audit-scope.json`
pins the source-hashed inventory, the security invariants, and the commands a
reviewer runs to reproduce results.

What remains is to commission the review. Until an assessor is engaged:

- `external_assessment.assessor` and `report_url` stay `null` and the status
  stays `ready-for-independent-review`. Those fields are the single source of
  truth for whether an audit exists.
- No acceptance criterion that depends on the assessor may be marked complete
  anywhere else, including issue checklists. Issue #145 currently has all six
  boxes checked while the audit metadata is empty; the metadata is correct and
  the checkboxes are not.

Once an assessor is engaged, the remaining work is ordinary:

- Fix or explicitly risk-accept findings and publish scope limitations.
- Reproduce release artifacts, proof bundles, and test results from clean
  environments.
- Add signed releases and provenance attestations where the release workflow
  supports them.
- Treat external users, plugins, corpora, and reported misses as validation
  evidence; repository activity alone is not adoption proof.

## Pull-request rules during the depth phase

- One measurable hardening objective per focused branch.
- No direct changes to `main`; use a draft PR and require green CI.
- Every behavior change includes positive and adversarial negative tests.
- Generated metrics/proof files are refreshed in the same PR.
- Claims state corpus size and limitations; synthetic perfection is never
  presented as field accuracy.
- Major new modes, editions, or subsystems remain deferred until this document's
  measurement foundations and core assurance ratchets are established.

## Progress

| Slice | Status | Exit evidence |
|---|---|---|
| D1 detection-quality foundation | Complete | Live rule parity, `TITAN-008`, 2+ positives and 2+ targeted near-misses per rule, risk separation, and full CI |
| D2 detection-content scale | In progress | 48-case native and 32-case YARA corpora; scheduled-task batch adds two variants, three native near-misses, decoded-child coverage, and multi-rule interactions |
| D3 decoder/analyzer parity | In progress | 44/44 live built-ins have positive/negative recognition plus malformed/truncated coverage; host-embedded engine cases cover 23/26 decoder positives with three recorded misses; nested chains are measured at engine level (20/21) because the class is not expressible per component; all 20 amplifying components (9 decoders, 11 analyzers) carry size-bound cases and the declared bound is enforced, not just its presence |
| D4 continuous adversarial testing | In progress | Weekly 30-minute campaign covers six surfaces, records iterations/unique inputs/violations, and retains deletion-minimized reproducers for 30 days |
| D5 code-assurance ratchet | In progress | CI floor raised from 70% to 75%; mypy exemption list emptied: every module type-checks with no ignore_errors, guarded by a test; property checks cover ordering, deduplication, bounds, and coercion |
| D6 determinism/provenance | In progress | Golden, lineage, and legacy report/workspace/plugin fixtures run on Linux plus Windows Python 3.10–3.13; migration matrix is published |
| D7 performance/operations | In progress | Unenforceable bounds are reported as run limitations instead of degrading silently, the memory ceiling uses a stdlib fallback, and supervised workers now enforce timeout/memory with real kill authority on the single-file and deep-scan paths; amplification, concurrency, and platform smoke gates continue |
| D8 independent validation | Outreach, not engineering | Commission an assessor; `parser-audit-scope.json` already pins scope, invariants, and reproduction commands |
