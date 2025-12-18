# Titan Decoder Engine

**Advanced payload decoding and forensic analysis framework for cybersecurity professionals, malware analysts, and law enforcement.**

[![Tests](https://img.shields.io/badge/tests-41%20passing-success)]() [![Python](https://img.shields.io/badge/python-3.9%2B-blue)]()

## 🚀 Quick Start (5 Minutes)

### 1. Install

```bash
# Clone repository
git clone https://github.com/pragmaconflux/titan1.git
cd titan1

# Install core only (no external dependencies)
pip install -e .

# OR install with all features
pip install -r requirements.txt
pip install -e .
```

### 2. Analyze Your First File

```bash
# Quick analysis
titan-decoder --file suspicious.bin --out report.json

# With progress and detections
titan-decoder --file payload.dat --progress --enable-detections

# Full law enforcement package
titan-decoder --file evidence.bin --profile full --enable-detections \\
    --forensics-out forensics.json --ioc-out iocs.json --ioc-format misp \\
    --report-out case_report.md --timeline-out timeline.csv
```

### 3. View Results

```bash
# Check the report
cat report.json | jq '.node_count, .iocs'

# View risk assessment
cat report.json | jq '.risk_score, .detections'
```

**That's it!** You're analyzing malware. 🎉

---

## 📋 Features

### Core Capabilities
- **20+ Decoders**: Base64, Gzip, Bz2, LZMA, Zlib, Hex, XOR, ROT13, PDF, OLE, UUencode, ASN.1, QuotedPrintable
- **Smart Detection**: Auto-enables format-specific decoders
- **Recursive Analysis**: Handles nested encodings (configurable depth)
- **Archive Support**: ZIP, TAR with anti-zip-bomb protections
- **Binary Analysis**: PE, ELF metadata extraction
- **IOC Extraction**: IPs, URLs, domains, emails, hashes with normalization

### Forensics & Intelligence
- **Device Forensics**: VM detection, mobile IDs (IMEI/IMSI/ICCID), burner patterns
- **7 Detection Rules**: LOLBins, Office macros, XOR+C2, deep Base64, packed payloads
- **Risk Scoring**: 0-100 heuristic threat assessment (CLEAN/LOW/MEDIUM/HIGH/CRITICAL)
- **Enrichment**: Geo/WHOIS/YARA (optional, requires config)
- **AV Intelligence**: VirusTotal lookups (optional API key)

### Export & Reporting
- **IOC Formats**: JSON, CSV, STIX 2.1, MISP
- **Case Reports**: Markdown summaries for investigators
- **Timeline Export**: CSV/JSON for Timesketch, Excel
- **Graph Export**: JSON, DOT, Mermaid

### Production Features
- **Batch Processing**: Analyze entire directories
- **PII Redaction**: Safe log sharing
- **Resource Limits**: Memory caps, timeouts
- **Signal Handling**: Clean shutdown (Ctrl+C)
- **Error Recovery**: Graceful handling of corrupted files

## Installation

### Option 1: Core Only (No Dependencies)

```bash
git clone https://github.com/pragmaconflux/titan1.git
cd titan1
pip install -e .
```

### Option 2: Full Featured

```bash
git clone https://github.com/pragmaconflux/titan1.git
cd titan1
pip install -r requirements.txt  # installs psutil, geoip2, yara-python, etc.
pip install -e .
```

---

## 📖 Usage Examples

### Command Line

**Basic Analysis**
```bash
titan-decoder --file payload.dat --out report.json --verbose
```

**Fast Triage** (depth=3, 50 max artifacts)
```bash
titan-decoder --file suspicious.bin --profile fast --progress --enable-detections
```

**Deep Analysis** (depth=8, 200 max artifacts)
```bash
titan-decoder --file malware.bin --profile full --enable-detections --enable-enrichment
```

**Law Enforcement Package**
```bash
titan-decoder --file evidence.bin --enable-detections \\
    --forensics-out forensics.json \\
    --ioc-out iocs.json --ioc-format misp \\
    --report-out case_report.md \\
    --timeline-out timeline.csv
```

**Batch Processing**
```bash
titan-decoder --batch ./input_dir --batch-pattern "*.bin" --out ./reports
```

### Python API

```python
from titan_decoder.core.engine import TitanEngine
from titan_decoder.core.detection_rules import CorrelationRulesEngine
from titan_decoder.core.risk_scoring import RiskScoringEngine
from titan_decoder.config import Config

# Basic analysis
engine = TitanEngine()
report = engine.run_analysis(data_bytes)

# With detections and risk scoring
rules = CorrelationRulesEngine()
detections = rules.evaluate_all(report, report['iocs'])

risk_engine = RiskScoringEngine()
risk = risk_engine.compute_risk_score(report, report['iocs'], detections)

print(f"Risk Level: {risk['risk_level']} ({risk['risk_score']}/100)")
print(f"Detections: {len(detections)}")
print(f"IOCs: {sum(len(v) for v in report['iocs'].values())}")
```

---

## ⚙️ Configuration

### Quick Config

Create `~/.titan_decoder/config.json`:

```json
{
    "max_recursion_depth": 5,
    "max_node_count": 100,
    "enable_logging": true,
    "log_level": "INFO"
}
```

### Full Configuration

```json
{
    "max_recursion_depth": 5,
    "max_node_count": 100,
    "max_data_size": 52428800,
    "analysis_timeout_seconds": 300,
    "max_memory_mb": 1024,
  
    "decoders": {
        "base64": true,
        "gzip": true,
        "hex": true,
        "xor": true,
        "pdf": true
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
    "yara_rules_path": "/path/to/rules.yar",
  
    "virustotal_api_key": "YOUR_API_KEY",
    "virustotal_rate_limit": 4,
  
    "enable_pii_redaction": true,
    "enable_logging": true,
    "log_level": "INFO"
}
```

Run `titan-decoder --help` for the full option list.

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=titan_decoder --cov-report=html

# Quick smoke test
echo 'ZGF0YTogdGVzdA==' | python -c 'import sys,base64; from titan_decoder.core.engine import TitanEngine; data=base64.b64decode(sys.stdin.read().strip()); print(TitanEngine().run_analysis(data)["node_count"])'
```

---

---

## 📚 Documentation

- **This README** - Installation, usage, configuration examples
- **CLI help** - Run `titan-decoder --help` for the full option list

---

## 🔒 Safety Recommendations

**Analyze untrusted files safely:**

1. **Dedicated VM**: Run in a disposable virtual machine
2. **Dedicated VM**: Run in disposable virtual machine
3. **Network isolation**: Disconnect network before analysis
4. **Non-root**: Never run as root user
5. **Resource limits**: Set max_memory_mb and analysis_timeout_seconds

---

## 🏗️ Architecture

```
titan_decoder/
├── cli.py                    # Command-line interface
├── config.py                 # Configuration management
├── core/
│   ├── engine.py             # Main analysis engine
│   ├── detection_rules.py    # 7 starter detection rules
│   ├── risk_scoring.py       # Heuristic threat assessment
│   ├── enrichment.py         # Geo/WHOIS/YARA
│   ├── device_forensics.py   # VM/mobile/burner detection
│   ├── ioc_export.py         # JSON/CSV/STIX/MISP export
│   ├── case_report.py        # Markdown reports
│   ├── timeline.py           # Event timeline export
│   ├── file_hashing.py       # MD5/SHA1/SHA256 + VT
│   ├── correlation.py        # IOC correlation cache
│   ├── resource_manager.py   # Timeouts and limits
│   ├── secure_logging.py     # PII redaction
│   ├── smart_detection.py    # Format auto-detection
│   ├── scoring.py            # Decode scoring
│   ├── profiling.py          # Performance metrics
│   ├── graph_export.py       # Graph visualization
│   └── analyzers/
│       └── base.py           # ZIP, TAR, PE, ELF
├── decoders/
│   └── base.py               # 20+ decoders
├── plugins/                  # Plugin system
└── utils/
        └── helpers.py            # IOC extraction, entropy
```

---

## 🤝 Contributing

Contributions welcome! Please open a PR or issue to discuss changes.

**Add a custom decoder:**
```python
from titan_decoder.plugins import PluginDecoder

class MyDecoder(PluginDecoder):
        @property
        def name(self) -> str:
                return "MyFormat"
    
        def can_decode(self, data: bytes) -> bool:
                return data.startswith(b"MYMAGIC")
    
        def decode(self, data: bytes) -> tuple[bytes, bool]:
                decoded = my_decode_logic(data)
                return decoded, True
```

Place in `~/.titan_decoder/plugins/my_decoder.py` and it's auto-loaded!

---

## 📄 License

License: MIT (add a LICENSE file if you plan to redistribute).

---

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/pragmaconflux/titan1/issues)

---

## 🎯 Roadmap

- [ ] REST API for integration
- [ ] Watch mode for directory monitoring
- [ ] Artifact parsers (prefetch, shimcache, browser history)
- [ ] PyPI package
- [ ] Single-file executable
- [ ] Web UI

---

## 🙏 Credits

Built with ❤️ for the cybersecurity community.

**Key Technologies:**
- Python 3.9+ (stdlib only for core)
- Optional: psutil, geoip2, yara-python, requests

---

**Ready to analyze? Start with:** `titan-decoder --file your_sample.bin --progress --enable-detections`
config = Config()
config.set("max_recursion_depth", 10)
engine = TitanEngine(config)
report = engine.run_analysis(data_bytes)

print(f"Found {report['node_count']} analysis nodes")
```

## Configuration

Create `~/.titan_decoder/config.json`:

```json
{
  "max_recursion_depth": 5,
  "max_zip_files": 25,
  "max_zip_total_size": 10485760,
  "enable_logging": true,
  "log_level": "INFO",
  "decoders": {
    "base64": true,
    "recursive_base64": true,
    "gzip": true,
    "bz2": true,
    "lzma": true,
    "hex": true,
    "rot13": true,
    "xor": true
  },
  "analyzers": {
    "zip": true,
    "tar": true
  }
}
```

## Architecture

```
titan_decoder/
├── __init__.py
├── cli.py                 # Command-line interface
├── config.py              # Configuration management
├── core/
│   ├── __init__.py
│   ├── engine.py          # Main analysis engine
│   └── analyzers/         # Archive analyzers
│       ├── __init__.py
│       └── base.py
├── decoders/              # Decoding modules
│   ├── __init__.py
│   └── base.py
└── utils/
    ├── __init__.py
    └── helpers.py         # Utility functions
```

## Extending the Engine

### Adding a New Decoder

```python
from titan_decoder.decoders.base import Decoder

class MyDecoder(Decoder):
    def can_decode(self, data: bytes) -> bool:
        return data.startswith(b"MYFORMAT")

    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        try:
            decoded = my_decode_function(data)
            return decoded, True
        except:
            return data, False

    @property
    def name(self) -> str:
        return "MyDecoder"
```

### Adding a New Analyzer

```python
from titan_decoder.core.analyzers.base import Analyzer

class MyAnalyzer(Analyzer):
    def can_analyze(self, data: bytes) -> bool:
        return data.startswith(b"MYARCHIVE")

    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        return [("file1.txt", b"content1"), ("file2.txt", b"content2")]

    @property
    def name(self) -> str:
        return "MyAnalyzer"
```

## Testing

```bash
pytest tests/
```

## Safety Features

- **Recursion Limits**: Prevents infinite loops in nested encodings
- **Size Limits**: Prevents extraction of excessively large archives
- **File Count Limits**: Prevents extraction of too many files from archives
- **Timeout Protection**: Built-in protections against hanging operations

## Performance

The engine is optimized for:
- Fast format detection
- Efficient memory usage
- Parallel analysis of archive contents
- Configurable resource limits

## License

MIT License

## Contributing

Contributions welcome! Please submit issues and pull requests on GitHub.