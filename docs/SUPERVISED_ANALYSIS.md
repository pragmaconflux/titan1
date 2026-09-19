# Supervised core analysis (opt-in)

This first increment runs the core decoder/analyzer in a disposable spawned
process. The standalone module returns core analysis only. DeepScanner and the
deep-scan CLI can now opt in and run the existing static checks inside the same
worker, retaining access to extracted payload bytes. Other CLI, desktop,
workbench and service paths remain unchanged. A successful report is not a
clean verdict.

From an installed checkout:

```powershell
python -m titan_decoder.core.supervised_analysis --file sample.bin --timeout 30 --max-memory-mb 1024
```

For recursive static scanning, use:

```powershell
python -m titan_decoder.cli --deep-scan samples --deep-scan-supervised --offline --stdout json
```

The deep-scan path preserves file-level progress, native rules, extracted-string
and YARA checks, risk/intelligence, assurance verdicts, report persistence, and
explicitly requested quarantine. It has no per-parser progress stream yet.
Worker failures are `INDETERMINATE` entries in the summary's `errors`, never
successful results; they produce no report or quarantine action. The CLI exits
nonzero on errors, cancellation, or a candidate-count limit. Existing
unsupervised behavior is unchanged. External providers (including Authenticode)
and plugin directories are rejected in this mode rather than silently skipped.

DeepScanner uses `analysis_timeout_seconds`, `max_memory_mb`, `max_data_size`,
and `supervised_max_output_bytes` (default 16 MiB). Timeout and memory values
must be positive; zero does not disable supervisor protections. The deadline
covers core analysis plus static checks, not discovery, report persistence or
quarantine in the parent. The API's `static_checks=True` enables this same
worker-local static pipeline.

The module prints the core JSON report on success. On failure it exits with code
2 and prints an `indeterminate` status and reason to stderr, without a partial
report. The Python API `analyze_supervised` returns a report or raises
`AnalysisTerminated` with a machine-readable `reason`. A caller can pass a
threading event as `cancel_event`; it is polled by the parent, not pickled into
the child. Use the usual `if __name__ == '__main__'` guard in calling scripts.

## Enforced boundaries

- The parent kills and reaps an unresponsive worker at its wall-clock deadline
  or on cancellation. Spawn time counts toward the deadline; process startup
  itself and OS termination latency are not a hard real-time guarantee.
- Input defaults to 50 MiB and serialized report output to 16 MiB. The CLI reads
  at most the input cap plus one byte. The worker limits JSON output while
  writing, and the parent checks the bound again before parsing.
- Memory defaults to 1024 MiB. Windows uses a Job Object process committed-memory
  limit; POSIX uses `RLIMIT_AS` (virtual address space). These are different OS
  allocation measurements, not comparable RSS budgets. Limit installation
  failure prevents analysis rather than silently dropping the limit.
- A Python socket guard is enabled in the worker. It is best effort, not an OS
  network sandbox. OS memory exhaustion can produce either `memory_limit` or
  `worker_failed` if the interpreter cannot produce an error record.
- This path uses built-in default configuration unless an explicit `Config`
  snapshot is passed to the API. It never silently loads user configuration.
  External plugin directories are rejected for now.

## Not guaranteed yet

This is not a security sandbox. Native code and the host filesystem remain in
the trusted base. Descendant process lifecycle containment, OS network and
filesystem restrictions, per-parser deadlines, streaming progress, and retained
partial evidence are not implemented. Parent JSON parsing also uses memory;
its bound is the serialized report cap, not the worker's allocation limit.

Next integration work should preserve those distinctions in every interface,
including explicit incomplete/indeterminate states and downstream artifact
scanning. Do not substitute the core-only result for a complete scan report.
