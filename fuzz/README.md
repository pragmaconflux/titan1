# Fuzzing

Titan has a fast decoder/analyzer gate for pull requests and a longer scheduled
campaign across six public-facing surfaces.

## Invariants (`invariants.py`)

Every decoder and analyzer must, on **any** input (random or malformed):

1. **Never raise uncaught** — signal failure via the `(data, False)` /
   empty-list contract, not exceptions.
2. **Never exceed the output cap** — bounded output (capped decoders honor
   `max_output_size`; the rest cannot balloon output).
3. **Always terminate quickly** — a single call finishes well under the
   engine's per-decode timeout.

`check_all(data)` runs one input through every built-in decoder plus the core
archive, executable, email, Office, RTF, script, LNK, MSI, and OneNote
analyzers and raises `InvariantError` on a violation.

## Running

Standalone, time-bounded (portable, no native deps):

```bash
python fuzz/fuzz_decoders.py --seconds 30
```

Cross-surface campaign:

```bash
python fuzz/fuzz_surfaces.py --seconds 300 --seed 145 --artifacts .fuzz-artifacts
```

The cross-surface harness covers decoder/analyzer contracts, evidence parsers,
plugin manifest and request transport, server request-length validation,
report loading and exports, and workspace load/save. It starts from the binary
corpus plus valid structured seeds so mutations reach both rejection and
successful-processing paths. Each run writes `summary.json` with its seed,
duration, iterations, unique inputs, surfaces, and violation categories.

The weekly GitHub Actions campaign runs for 30 minutes. On failure it retains
the exact input after deletion minimization, a metadata sidecar, and the run
summary for 30 days. The recorded seed makes the random stream reproducible.

End-to-end and complexity campaigns:

```bash
python fuzz/fuzz_e2e.py --seconds 600 --seed 7 --artifacts .fuzz-artifacts
python fuzz/fuzz_cli.py --seconds 600 --seed 11 --artifacts .fuzz-artifacts
python fuzz/fuzz_complexity.py --artifacts .fuzz-artifacts
```

- `fuzz_e2e.py` drives mutated inputs (seeded from every calibration case, the
  golden corpus, and `corpus/`) through `cli.main()` with every export on, and
  checks exit status, report schema, graph/provenance integrity, IOC shape,
  that every export parses, determinism across reruns, and that the analyst's
  deterministic answers pass its own citation validator.
- `fuzz_cli.py` covers the modes `fuzz_e2e.py` does not: batch, deep scan
  (supervised and with copy-mode quarantine), supervised single-file,
  correlation DB with every correlation export, vault, evidence ingestion
  with mutated CSV/JSONL for every kind, forensics, redaction, and profiling.
- `fuzz_complexity.py` runs every decoder, analyzer, and the full engine on
  61 input shapes at 8/32/128KB and flags super-linear growth. Crash fuzzing
  cannot see a quadratic path; this sweep found the quadratic IOC regexes and
  the Base58 big-integer decode.

All three exit 1 on any finding, keep the triggering input, and run weekly in
`.github/workflows/scheduled-fuzz.yml`.

In CI / pytest (bounded example budget + corpus replay):

```bash
pytest tests/test_fuzz_invariants.py
```

The property tests use [Hypothesis](https://hypothesis.readthedocs.io/) when it
is installed and are skipped otherwise; the corpus-replay test always runs.

## Corpus (`corpus/`)

Checked-in "interesting" seeds: empty input, format magic bytes with and
without valid structure, truncated CFB/PDF streams, nested base64, compression
containers, an XOR'd URL, PE/ELF stubs, UTF-16/URL/HTML/UU encodings, high-
entropy blobs, and mixed-magic junk. New crash-triggering inputs discovered by
the fuzzer should be minimized and added here as regression seeds. The
scheduled harness performs initial deletion minimization automatically; a
confirmed reproducer still belongs in this corpus with a focused regression
test.
