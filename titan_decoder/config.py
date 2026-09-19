import json
import copy
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class Config:
    """Configuration manager for Titan Decoder."""

    DEFAULT_CONFIG = {
        "max_recursion_depth": 5,
        "max_node_count": 100,
        "min_score_threshold": 0.01,  # Lower threshold for basic functionality
        "max_data_size": 50 * 1024 * 1024,  # 50MB
        # Resource limits / timeouts
        "analysis_timeout_seconds": 300,
        "decode_timeout_seconds": 10,
        "analyzer_timeout_seconds": 10,
        "max_memory_mb": 1024,
        # Output/telemetry
        "include_decision_trace": False,
        # Bytes of each node's content scanned for IOCs. Node previews are
        # capped at 2KB for reporting; indicators must be recovered from the
        # full artifact, so this bound is separate and much larger.
        "max_ioc_scan_bytes": 1024 * 1024,
        "max_zip_files": 25,
        "max_zip_total_size": 10 * 1024 * 1024,  # 10MB
        "max_zip_file_size": 50 * 1024 * 1024,  # 50MB per file
        "max_compression_ratio": 100,  # 100:1 max compression ratio
        # Bounded allowlist only; Titan never brute-forces archive passwords.
        "zip_passwords": ["infected"],
        "max_tar_files": 25,
        "max_tar_total_size": 10 * 1024 * 1024,  # 10MB
        "max_tar_file_size": 50 * 1024 * 1024,  # 50MB per file
        # Embedded-payload carving bounds. Carving recovers encoded regions
        # from inside a host file (a base64 blob in a script variable, a hex
        # blob in an XML attribute), which whole-buffer decoders cannot reach.
        "max_carved_artifacts": 8,
        "max_carved_artifact_size": 4 * 1024 * 1024,
        "max_carved_total_size": 16 * 1024 * 1024,
        "max_carve_scan_bytes": 4 * 1024 * 1024,
        "min_carved_run_length": 24,
        # Static image/media steganography extraction bounds.
        "max_media_artifacts": 8,
        "max_media_total_size": 8 * 1024 * 1024,
        "max_media_artifact_size": 4 * 1024 * 1024,
        "max_lsb_carrier_bytes": 4 * 1024 * 1024,
        "max_lsb_output_size": 1024 * 1024,
        # Pruning policies (each toggles a rule in PruningEngine)
        "enable_quality_pruning": True,
        "enable_resource_pruning": True,
        "enable_depth_based_limits": True,
        # Plugin system
        "plugin_dirs": [],
        "plugin_execution_mode": "isolated",
        "plugin_offline": True,
        "plugin_timeout_seconds": 10,
        "plugin_max_input_bytes": 100 * 1024 * 1024,
        "plugin_max_output_bytes": 16 * 1024 * 1024,
        "plugin_max_memory_mb": 512,
        "plugin_max_children": 100,
        "enable_logging": True,
        "log_level": "INFO",
        "decoders": {
            "base64": True,
            "recursive_base64": True,
            "base64url": True,
            "pem": True,
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
            "utf16": True,
            "ascii85": True,
            "raw_deflate": True,
            "powershell_encoded_command": True,
            "javascript_escape": True,
            "javascript_emulation": True,
            "base58": True,
            "base91": True,
            "brotli": True,
            "zstandard": True,
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
            "macho": True,
            "dex": True,
            "x86_shellcode_emulation": True,
            "embedded_payload": True,
            "steganography": True,
            "email": True,
            "office": True,
            "rtf": True,
            "script": True,
            "lnk": True,
            "msi": True,
            "onenote": True,
            "optional_archives": True,
            "virtual_disk": True,
        },
        # Structured artifact extraction bounds shared by email, Office,
        # script, shortcut, and optional archive analyzers.
        "max_structured_artifacts": 32,
        "max_structured_total_size": 16 * 1024 * 1024,
        "max_structured_artifact_size": 4 * 1024 * 1024,
        # Forensics / enrichment
        "enable_geo_enrichment": False,  # Optional MaxMind/GeoIP if available
        "geo_db_path": None,
        "enable_whois": False,  # Optional WHOIS lookups (if library present)
        # Deterministic enrichment caching
        "enable_enrichment_cache": True,
        "enrichment_cache_path": None,
        "enable_correlation": False,  # SQLite correlation cache
        "correlation_db_path": None,
        "enable_yara": False,  # Optional YARA scanning on decoded artifacts
        "yara_rules_path": None,
        # Additional YARA sources and bounds. Directories are compiled with
        # one namespace per rule file so match provenance survives merging.
        "yara_rules_files": [],  # list of individual rule files
        "yara_rules_dirs": [],  # list of directories of .yar/.yara files
        "yara_timeout_seconds": 10,  # per-payload scan timeout
        "yara_max_matches": 200,  # total matches recorded per run
        "yara_max_nodes": 300,  # payloads scanned per run (node order)
        "yara_max_meta_bytes": 4096,  # serialized meta captured per match
        "yara_max_strings_per_match": 8,
        "yara_max_string_bytes": 128,
        # Fail-closed assurance providers. Attestations are JSON documents named
        # <sha256>.json and are accepted only when their embedded hash matches.
        "enable_assurance": True,
        "malicious_hashes_path": None,
        "trusted_hashes_path": None,
        "sandbox_attestations_dir": None,
        "provenance_attestations_dir": None,
        # Optional trusted provider commands. Each value must be a JSON array
        # of argv tokens; Titan never invokes a shell. Supported placeholders
        # are {sample} and {sha256}. Providers return one JSON attestation on
        # stdout using the contracts documented in ASSURANCE_PIPELINE.md.
        "sandbox_provider_command": None,
        "provenance_provider_command": None,
        "assurance_provider_timeout_seconds": 120,
        "enable_authenticode_provider": False,
        # Reproducibility / strictness
        "seed": None,  # Optional deterministic seed recorded in run_manifest
        "strict": False,  # Optional CLI strict mode can enforce report contract
        "max_report_size_mb": None,  # Optional guard against huge report outputs
        # Detection rule packs (rules-as-data)
        "detection_rule_packs": [],  # list of JSON/YAML pack paths
        # Local vault (history/search)
        "vault_dir": None,  # default: ~/.titan_decoder/vault
        "vault_db_path": None,  # default: <vault_dir>/vault.db
        # Recursive static scanning and recoverable quarantine.
        "deep_scan_max_files": 10000,
        "deep_scan_max_total_bytes": 10 * 1024 * 1024 * 1024,
        "deep_scan_follow_symlinks": False,
        "quarantine_dir": None,  # default: ~/.titan_decoder/quarantine
        # Decoder/analyzer calibration quality gates.
        "calibration_min_precision": 0.90,
        "calibration_min_recall": 0.90,
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
            except Exception as e:
                # Fall back to defaults, but don't hide the problem: a typo'd
                # config silently reverting every setting is very confusing.
                logger.warning(
                    "Could not load config %s (%s); using defaults",
                    self.config_file,
                    e,
                )

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
