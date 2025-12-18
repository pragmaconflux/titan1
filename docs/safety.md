# Safety Guide

## Run in Isolation
- Prefer Docker or a disposable VM
- Disconnect network for untrusted samples (`--network none` in Docker)
- Avoid running as root

## Limit Resource Impact
- Set `max_node_count` and `max_recursion_depth`
- Use `--profile fast` for triage
- Configure `analysis_timeout_seconds` and `max_memory_mb`

## Protect Sensitive Data
- Keep `enable_pii_redaction` true (default)
- Store reports in controlled locations
- Avoid uploading samples to external services unless required

## VirusTotal Usage
- VT lookups send hashes to VirusTotal
- Use only when policy allows
- Rate limit via `virustotal_rate_limit`

## YARA and GeoIP
- Ensure YARA rules are trusted and maintained
- Keep GeoIP databases updated

## Logging
- Logs may contain decoded content previews
- Use redaction and restricted log destinations

## Checklist for Field Use
- [ ] Running in container/VM
- [ ] Network isolation applied if required
- [ ] PII redaction enabled
- [ ] Resource limits set (memory/timeout)
- [ ] VT key approved and configured (if used)
- [ ] YARA rules vetted and updated
