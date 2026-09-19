# Supervised core analysis (opt-in)

This first increment runs the core decoder/analyzer in a disposable spawned
process. It does not replace the existing CLI, desktop, workbench or service
execution paths yet. It does not add the CLI's downstream detection/enrichment
pipeline. A successful core report is not a clean verdict.

From an installed checkout:

```powershell
python -m titan_decoder.core.supervised_analysis --file sample.bin --timeout 30 --max-memory-mb 1024
```

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
