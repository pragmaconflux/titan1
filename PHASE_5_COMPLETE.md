# Titan Decoder Engine - Phase 5 Complete

## Major Enhancements Delivered

### 1. **Enrichment Engine** ([core/enrichment.py](titan_decoder/core/enrichment.py))
- Geo/WHOIS/YARA enrichment with graceful degradation
- Rate-limited WHOIS lookups with caching
- GeoIP2 integration for IP geolocation
- YARA scanning for decoded artifacts
- Optional, config-driven activation

### 2. **File Hashing & AV Intelligence** ([core/file_hashing.py](titan_decoder/core/file_hashing.py))
- MD5/SHA1/SHA256 hashing for all artifacts
- VirusTotal API integration (optional, rate-limited)
- Caching to avoid duplicate lookups
- Configurable rate limits

### 3. **Detection Rules Library** ([core/detection_rules.py](titan_decoder/core/detection_rules.py))
7 starter detection rules:
- **TITAN-001**: Deep Base64 nesting (3+ levels)
- **TITAN-002**: Office macro with network IOCs
- **TITAN-003**: LOLBin script execution patterns
- **TITAN-004**: Encrypted/packed payloads (high entropy)
- **TITAN-005**: Multi-stage infrastructure (multiple IOC types)
- **TITAN-006**: XOR obfuscation with C2
- **TITAN-007**: Malicious PDF (embedded executables)

### 4. **Risk Scoring Engine** ([core/risk_scoring.py](titan_decoder/core/risk_scoring.py))
- Heuristic threat assessment (0-100 score)
- Risk level classification (CLEAN/LOW/MEDIUM/HIGH/CRITICAL)
- Weighted scoring based on:
  - Detection rule severity
  - IOC counts and types
  - Obfuscation depth
  - Entropy levels
  - YARA matches
- Top 5 risk reasons reported
- Top risky nodes identification

### 5. **MISP Export** ([core/ioc_export.py](titan_decoder/core/ioc_export.py))
- Full MISP event format (JSON)
- Proper attribute mapping (ip-dst, url, domain, email, hash)
- UUID generation for events and attributes
- Configurable event metadata

### 6. **Secure Logging** ([core/secure_logging.py](titan_decoder/core/secure_logging.py))
- PII redaction for emails, IPs, hashes
- Structured logging with key=value pairs
- Configurable redaction (on by default)
- Operational safety for log sharing

### 7. **CLI Ergonomics** ([cli.py](titan_decoder/cli.py))
**New Flags**:
- `--profile fast|full`: Quick triage or deep analysis presets
- `--max-artifacts N`: Limit extracted artifacts
- `--progress`: Show progress updates during analysis
- `--enable-enrichment`: Activate geo/WHOIS/YARA
- `--enable-detections`: Run detection rules + risk scoring
- `--enable-redaction`: PII redaction in logs (default: on)
- `--ioc-format misp`: MISP export format added

**Enhanced Output**:
- Summary footer with key metrics
- IOC counts, detection counts
- Risk level and score display
- Top 3 risk factors

### 8. **Timeline Export** ([core/timeline.py](titan_decoder/core/timeline.py))
- CSV/JSON timeline of all analysis events
- Ordered by processing sequence
- Includes depth, method, decoder, size, hash
- Ready for external tool ingestion (Timesketch, Excel)

## Configuration Updates

New config options in [config.py](titan_decoder/config.py):
```python
"virustotal_api_key": None,        # Optional VT API key
"virustotal_rate_limit": 4,        # Requests per minute
"enable_pii_redaction": True,      # Redact PII from logs
```

## Test Coverage

**40 tests passing** (100% success):
- 4 new detection rules tests
- 3 new risk scoring tests
- 4 new secure logging tests
- All existing tests passing

## Usage Examples

**Fast Triage with Detection**:
```bash
titan-decoder --file suspicious.bin --profile fast --enable-detections --progress
```

**Full Analysis with Enrichment**:
```bash
titan-decoder --file payload.dat --profile full --enable-enrichment --enable-detections \
  --ioc-out iocs.json --ioc-format misp --report-out report.md --timeline-out timeline.csv
```

**Law Enforcement Package**:
```bash
titan-decoder --file evidence.bin --enable-detections --forensics-out forensics.json \
  --report-out case_report.md --ioc-out iocs_misp.json --ioc-format misp
```

## Next Steps (Optional Future Work)

Still on the wishlist but not yet implemented:
- Artifact parsers (prefetch, shimcache, amcache, browser history)
- Memory-lite process dump/strings capture
- CLI time filters (--since/--until)
- Packaging as single-file binary (shiv/pex)
- CI workflow with smoke tests

## Architecture

All new modules follow the defensive/forensic philosophy:
- Opt-in activation via config/CLI flags
- Graceful degradation when dependencies missing
- Rate limiting and caching for external services
- No offensive capabilities
- PII protection by default
