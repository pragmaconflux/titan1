"""
Plugin system for Titan Decoder Engine.

This module provides the base classes and loading mechanisms for extending
the decoder engine with custom decoders and analyzers.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Tuple
import importlib.util
import sys
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class PluginDecoder(ABC):
    """Base class for plugin decoders."""

    @abstractmethod
    def can_decode(self, data: bytes) -> bool:
        """Check if this decoder can handle the data."""
        pass

    @abstractmethod
    def decode(self, data: bytes) -> Tuple[bytes, bool]:
        """Decode the data. Return (decoded_data, success)."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the decoder."""
        pass

    @property
    def priority(self) -> int:
        """Priority for decoder ordering (higher = tried first). Default 0."""
        return 0


class PluginAnalyzer(ABC):
    """Base class for plugin analyzers."""

    @abstractmethod
    def can_analyze(self, data: bytes) -> bool:
        """Check if this analyzer can handle the data."""
        pass

    @abstractmethod
    def analyze(self, data: bytes) -> List[Tuple[str, bytes]]:
        """Analyze the data and return list of (name, content) tuples."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer."""
        pass

    @property
    def priority(self) -> int:
        """Priority for analyzer ordering (higher = tried first). Default 0."""
        return 0


class PluginManager:
    """Manages loading and registration of plugins."""

    def __init__(self, plugin_dirs: List[Path] = None):
        self.plugin_dirs = plugin_dirs or []
        self.decoders: List[PluginDecoder] = []
        self.analyzers: List[PluginAnalyzer] = []
        self.loaded_plugins: Dict[str, Any] = {}

    def add_plugin_dir(self, plugin_dir: Path):
        """Add a directory to search for plugins."""
        if plugin_dir not in self.plugin_dirs:
            self.plugin_dirs.append(plugin_dir)

    def load_plugins(self):
        """Load all plugins from configured directories."""
        for plugin_dir in self.plugin_dirs:
            if plugin_dir.exists() and plugin_dir.is_dir():
                self._load_plugins_from_dir(plugin_dir)

        # Sort by priority (highest first)
        self.decoders.sort(key=lambda d: d.priority, reverse=True)
        self.analyzers.sort(key=lambda a: a.priority, reverse=True)

    def _load_plugins_from_dir(self, plugin_dir: Path):
        """Load plugins from a specific directory."""
        for item in plugin_dir.iterdir():
            if (
                item.is_file()
                and item.suffix == ".py"
                and not item.name.startswith("_")
            ):
                self._load_plugin_file(item)

    def _load_plugin_file(self, plugin_file: Path):
        """Load a single plugin file."""
        try:
            # Create module name
            module_name = f"titan_decoder_plugins_{plugin_file.stem}"

            # Load the module
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                # Find plugin classes in the module
                self._register_plugin_classes(module, plugin_file.stem)

                self.loaded_plugins[plugin_file.stem] = module

        except Exception as e:
            logger.warning("Failed to load plugin %s: %s", plugin_file, e)

    def _register_plugin_classes(self, module, plugin_name: str):
        """Register plugin classes from a loaded module."""
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type):
                # Check if it's a plugin class
                if issubclass(attr, PluginDecoder) and attr != PluginDecoder:
                    try:
                        instance = attr()
                        self.decoders.append(instance)
                        logger.info("Loaded decoder plugin: %s", instance.name)
                    except Exception as e:
                        logger.warning(
                            "Failed to instantiate decoder %s from plugin %s: %s",
                            attr_name,
                            plugin_name,
                            e,
                        )

                elif issubclass(attr, PluginAnalyzer) and attr != PluginAnalyzer:
                    try:
                        instance = attr()
                        self.analyzers.append(instance)
                        logger.info("Loaded analyzer plugin: %s", instance.name)
                    except Exception as e:
                        logger.warning(
                            "Failed to instantiate analyzer %s from plugin %s: %s",
                            attr_name,
                            plugin_name,
                            e,
                        )

    def get_decoders(self) -> List[PluginDecoder]:
        """Get all loaded decoder plugins."""
        return self.decoders.copy()

    def get_analyzers(self) -> List[PluginAnalyzer]:
        """Get all loaded analyzer plugins."""
        return self.analyzers.copy()

    def get_plugin_info(self) -> Dict[str, Any]:
        """Get information about loaded plugins."""
        return {
            "plugin_dirs": [str(d) for d in self.plugin_dirs],
            "loaded_plugins": list(self.loaded_plugins.keys()),
            "decoders": [d.name for d in self.decoders],
            "analyzers": [a.name for a in self.analyzers],
        }
