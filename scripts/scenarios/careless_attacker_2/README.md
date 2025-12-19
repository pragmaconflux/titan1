# Careless attacker scenario #2

This folder contains a **safe, synthetic** payload capture that simulates an attacker doing a poor job of OPSEC.

## Files
- `payload_capture.txt`: single-file artifact with email headers + stager + HTTP headers + misc hints.
- `config_enrichment_example.json`: example config enabling WHOIS enrichment.

## Run
```bash
# Basic run (extract IOCs + forensics)
titan-decoder --file scripts/scenarios/careless_attacker_2/payload_capture.txt \
  --profile full --enable-detections --forensics-print \
  --out /tmp/titan_report.json --ioc-out /tmp/titan_iocs.json

# With enrichment (WHOIS/Geo if configured)
titan-decoder --file scripts/scenarios/careless_attacker_2/payload_capture.txt \
  --config scripts/scenarios/careless_attacker_2/config_enrichment_example.json \
  --enable-enrichment --profile full --enable-detections --forensics-print \
  --out /tmp/titan_report.json --ioc-out /tmp/titan_iocs.json
```

## Notes
- Geo enrichment requires a GeoIP database file (`geo_db_path`) and the `geoip2` Python package.
- The payload uses public IPs as stand-ins so enrichment can return something; replace with observed IPs for real investigations.
