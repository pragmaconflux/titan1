# Troubleshooting

## Common Issues

### Missing Dependencies
- **Symptom:** ImportError for geoip2, yara, whois, psutil
- **Fix:** `pip install -r requirements.txt` or `pip install -r requirements-optional.txt`

### GeoIP Not Working
- **Symptom:** GeoIP lookup returns None
- **Fix:** Download GeoLite2 City database and set `geo_db_path` in config

### VirusTotal Rate Limit
- **Symptom:** `{ "_rate_limited": true }`
- **Fix:** Lower `virustotal_rate_limit` or wait; ensure API key is set

### YARA Errors
- **Symptom:** YARA compile/scan failure
- **Fix:** Validate rules; ensure `yara_rules_path` exists and is readable

### Out of Memory
- **Symptom:** Process killed or MemoryError
- **Fix:** Lower `max_node_count`, `max_recursion_depth`; enable `profile fast`; set `max_memory_mb`

### Timeout
- **Symptom:** Analysis stops with timeout
- **Fix:** Increase `analysis_timeout_seconds`; reduce input size; use `--profile fast`

### Broken Pipe
- **Symptom:** Printing to piped commands causes error
- **Fix:** Safe-handled in CLI; re-run without piping or redirect output to file

## Safe Operation
- Run in Docker or VM
- Use `--enable-redaction` (default) to protect PII in logs
- Use `--profile fast` for quick triage under resource constraints

## Getting Help
- Run with `--verbose` to see stack traces on errors
- Open an issue: https://github.com/launchfailure/titan1/issues
