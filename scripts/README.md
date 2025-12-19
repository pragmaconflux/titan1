# Scripts

This folder contains developer/operator tooling for Titan.

## Stress test runner
- File: `scripts/stress_test_engine.py`
- Purpose: run repeatable timing + memory stress runs against synthetic scenarios and/or a real payload corpus.

Examples:
```bash
python scripts/stress_test_engine.py --iterations 50 --scenario all
python scripts/stress_test_engine.py --payload-dir /path/to/payloads --payload-sample 200 --payload-repeat 2 --iterations 1
```

## Scenarios
- `scripts/scenarios/`: safe, synthetic payload packs you can analyze with Titan.

Example:
```bash
python -m titan_decoder.cli --file scripts/scenarios/careless_attacker_2/payload_capture.txt \
  --profile full --enable-detections --forensics-print \
  --out /tmp/titan_report.json --ioc-out /tmp/titan_iocs.json
```
