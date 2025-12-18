import json
from pathlib import Path
from typing import Dict, Any


class Config:
    """Configuration manager for Titan Decoder."""

    DEFAULT_CONFIG = {
        "max_recursion_depth": 5,
        "max_node_count": 100,
        "min_score_threshold": 0.01,  # Lower threshold for basic functionality
        "max_data_size": 50 * 1024 * 1024,  # 50MB
        "max_zip_files": 25,
        "max_zip_total_size": 10 * 1024 * 1024,  # 10MB
        "enable_logging": True,
        "log_level": "INFO",
        "decoders": {
            "base64": True,
            "recursive_base64": True,
            "gzip": True,
            "bz2": True,
            "lzma": True,
            "hex": True,
            "rot13": True,
            "xor": True,
        },
        "analyzers": {
            "zip": True,
            "tar": True,
        }
    }

    def __init__(self, config_file: Path = None):
        self.config_file = config_file or Path.home() / ".titan_decoder" / "config.json"
        self._config = self.DEFAULT_CONFIG.copy()
        self.load()

    def load(self):
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    loaded = json.load(f)
                    self._config.update(loaded)
            except Exception:
                pass  # Use defaults

    def save(self):
        """Save configuration to file."""
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_file, 'w') as f:
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