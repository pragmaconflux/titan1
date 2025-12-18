# Titan Decoder Engine

A comprehensive, modular payload decoding and analysis framework designed for cybersecurity professionals and malware analysts.

## Features

- **Multi-format Decoding**: Supports Base64, Recursive Base64, Gzip, Bz2, LZMA, Hex, ROT13, and XOR decoding
- **Archive Analysis**: Handles ZIP and TAR files with safety limits
- **Recursive Analysis**: Automatically decodes nested encodings up to configurable depth
- **IOC Extraction**: Extracts IPs, URLs, domains, emails, and hashes from decoded content
- **Modular Architecture**: Extensible plugin system for custom decoders and analyzers
- **Configuration System**: JSON-based configuration with user defaults
- **CLI Interface**: Command-line tool with extensive options
- **Safety Limits**: Configurable limits to prevent resource exhaustion
- **Comprehensive Logging**: Detailed analysis logging for debugging

## Installation

```bash
pip install -e .
```

## Usage

### Command Line

```bash
# Basic usage
titan-decoder --file malware.bin --out report.json

# With custom config
titan-decoder --file malware.bin --config my_config.json --verbose

# Override recursion depth
titan-decoder --file malware.bin --max-depth 10
```

### Python API

```python
from titan_decoder.core.engine import TitanEngine
from titan_decoder.config import Config

# Use default config
engine = TitanEngine()
report = engine.run_analysis(data_bytes)

# Use custom config
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