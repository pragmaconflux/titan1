import json
import copy
from pathlib import Path
from typing import Any


class Config:
    """Configuration manager for Titan Decoder."""

    DEFAULT_CONFIG = {
        "max_recursion_depth": 5,
        "max_node_count": 100,
        "min_score_threshold": 0.01,  # Lower threshold for basic functionality
        "max_data_size": 50 * 1024 * 1024,  # 50MB
        "max_zip_files": 25,
        "max_zip_total_size": 10 * 1024 * 1024,  # 10MB
        "max_zip_file_size": 50 * 1024 * 1024,  # 50MB per file
        "max_compression_ratio": 100,  # 100:1 max compression ratio
        "max_tar_files": 25,
        "max_tar_total_size": 10 * 1024 * 1024,  # 10MB
        "max_tar_file_size": 50 * 1024 * 1024,  # 50MB per file
        # Enhanced pruning policies
        "enable_quality_pruning": True,
        "enable_resource_pruning": True,
        "enable_depth_based_limits": True,
        "quality_decay_threshold": 0.05,
        "max_consecutive_low_scores": 3,
        "min_content_similarity": 0.8,
        "prune_empty_decodes": True,
        "prune_identical_content": True,
        # Parallel processing
        "enable_parallel_extraction": True,
        "max_parallel_workers": 4,
        # Plugin system
        "plugin_dirs": [],
        "enable_logging": True,
        "log_level": "INFO",
        "decoders": {
            "base64": True,
            "recursive_base64": True,
            "gzip": True,
            "bz2": True,
            "lzma": True,
            "zlib": True,
            "hex": True,
            "rot13": True,
            "xor": True,
            "pdf": True,
            "ole": True,
            # New decoders (Phase 7)
            "url": True,
            "html_entity": True,
            "unicode_escape": True,
            "base85": True,
            # Off-by-default decoders (require smart detection)
            "uuencode": False,
            "asn1": False,
            "quoted_printable": False,
            "base32": False,
        },
        "analyzers": {
            "zip": True,
            "tar": True,
            "pe": True,
            "elf": True,
        },
        # Phase 7: Advanced analysis
        "enable_entropy_analysis": True,
        "enable_script_analysis": True,
        "enable_shellcode_detection": True,
        "enable_string_extraction": True,
        "enable_xor_keyfinding": True,
        "enable_polymorphic_detection": True,
        "enable_yara_generation": True,
        "enable_html_reports": True,
        # Forensics / enrichment
        "enable_geo_enrichment": False,  # Optional MaxMind/GeoIP if available
        "geo_db_path": None,
        "enable_whois": False,  # Optional WHOIS lookups (if library present)
        "enable_correlation": False,  # SQLite correlation cache
        "correlation_db_path": None,
        "enable_yara": False,  # Optional YARA scanning on decoded artifacts
        "yara_rules_path": None,
        # AV Intelligence
        "virustotal_api_key": None,  # Optional VirusTotal API key
        "virustotal_rate_limit": 4,  # Requests per minute
        # Security / Privacy
        "enable_pii_redaction": True,  # Redact PII from logs
    }

    def __init__(self, config_file: Path = None):
        self.config_file = config_file or Path.home() / ".titan_decoder" / "config.json"
        # Deep-copy to avoid shared nested dict mutation across Config instances.
        self._config = copy.deepcopy(self.DEFAULT_CONFIG)
        self.load()

    @staticmethod
    def _deep_update(dst: dict, src: dict) -> dict:
        """Recursively merge src into dst (dicts only)."""
        for key, value in (src or {}).items():
            if isinstance(value, dict) and isinstance(dst.get(key), dict):
                Config._deep_update(dst[key], value)
            else:
                dst[key] = value
        return dst

    def load(self):
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    loaded = json.load(f)
                    # Allow partial nested overrides (e.g. only set one decoder flag)
                    # without wiping the rest of the defaults.
                    if isinstance(loaded, dict):
                        self._deep_update(self._config, loaded)
            except Exception:
                pass  # Use defaults

    def save(self):
        """Save configuration to file."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, "w") as f:
            json.dump(self._config, f, indent=2)

    def get(self, key: str, default=None):
        """Get configuration value."""
        return self._config.get(key, default)

    def set(self, key: str, value: Any):
        """Set configuration value."""
        self._config[key] = value

    def __getitem__(self, key: str):
        return self._config[key]

    def __setitem__(self, key: str, value: Any):
        self._config[key] = value
