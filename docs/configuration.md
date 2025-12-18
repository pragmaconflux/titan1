# Configuration Guide

Place your config at `~/.titan_decoder/config.json` or supply via `--config path.json`.

## Core Limits
- `max_recursion_depth` (int): Maximum decode depth (default: 5)
- `max_node_count` (int): Maximum artifacts/nodes (default: 100)
- `max_data_size` (bytes): Max input size (default: 50MB)
- `max_memory_mb` (int): Memory cap before abort (default: 1024)
- `analysis_timeout_seconds` (int): Global analysis timeout (default: 300)

## Decoders
Enable/disable by name under `decoders`:
- `base64`, `recursive_base64`, `gzip`, `bz2`, `lzma`, `zlib`, `hex`, `rot13`, `xor`, `pdf`, `ole`, `uuencode`, `asn1`, `quoted_printable`, `base32`

## Analyzers
Enable/disable under `analyzers`:
- `zip`, `tar`, `pe`, `elf`

## Enrichment & Intelligence
- `enable_geo_enrichment`: bool
- `geo_db_path`: path to MaxMind database
- `enable_whois`: bool
- `enable_yara`: bool
- `yara_rules_path`: path to YARA rules
- `virustotal_api_key`: API key for VirusTotal
- `virustotal_rate_limit`: requests per minute

## Correlation & Reporting
- `enable_correlation`: bool
- `correlation_db_path`: path to SQLite cache
- `enable_pii_redaction`: bool (default: true)

## Logging
- `enable_logging`: bool
- `log_level`: `DEBUG|INFO|WARN|ERROR`

## Example Minimal Config
```json
{
  "max_recursion_depth": 5,
  "max_node_count": 100,
  "enable_logging": true,
  "log_level": "INFO"
}
```

## Example Full Config
```json
{
  "max_recursion_depth": 8,
  "max_node_count": 200,
  "max_data_size": 104857600,
  "analysis_timeout_seconds": 300,
  "max_memory_mb": 1024,
  "decoders": {
    "base64": true,
    "gzip": true,
    "hex": true,
    "xor": true,
    "pdf": true,
    "ole": true,
    "uuencode": true,
    "asn1": true
  },
  "analyzers": {
    "zip": true,
    "tar": true,
    "pe": true,
    "elf": true
  },
  "enable_geo_enrichment": false,
  "enable_whois": false,
  "enable_yara": false,
  "yara_rules_path": "/rules/corp_rules.yar",
  "virustotal_api_key": "YOUR_API_KEY",
  "virustotal_rate_limit": 4,
  "enable_pii_redaction": true,
  "enable_logging": true,
  "log_level": "INFO"
}
```