"""Kasra L3 Rule Engine — Configuration loader.

The :class:`ConfigLoader` reads YAML from two files (defaults + overrides),
deep-merges them, and returns a validated ``GlobalConfig`` instance.

File resolution (in order):
  1. ``<package_root>/../../config/default.yaml``  (shipped defaults)
  2. ``<package_root>/../../config/override.yaml``  (user overrides — optional)

Environment variables with the ``KASRA_`` prefix are layered on top
automatically by ``pydantic-settings``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from kasra.config.global_config import GlobalConfig
from kasra.exceptions.errors import ConfigError


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base* and return a new dict."""
    merged = base.copy()
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged


class ConfigLoader:
    """Loads and validates Kasra configuration from YAML files + env vars."""

    def __init__(self, config_dir: str | os.PathLike | None = None) -> None:
        """Initialise the loader.

        Args:
            config_dir: Optional explicit config directory path.
                        If ``None``, the directory is auto-detected via
                        :func:`kasra.utils.package.find_data_dir`.
        """
        if config_dir is not None:
            self._config_dir = Path(config_dir).resolve()
        else:
            from kasra.utils.package import find_data_dir
            self._config_dir = find_data_dir("config")
            self._config_dir = self._config_dir.resolve()

    @property
    def config_dir(self) -> Path:
        return self._config_dir

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> GlobalConfig:
        """Load, merge, and return the validated configuration.

        Returns:
            A ``GlobalConfig`` instance with all layers applied.

        Raises:
            ConfigError: If the defaults file exists but is unreadable.
        """
        raw: dict[str, Any] = {}

        # 1. Defaults
        default_path = self._config_dir / "default.yaml"
        if default_path.is_file():
            try:
                raw = self._load_yaml(default_path)
            except OSError as exc:
                raise ConfigError(f"Cannot read defaults file: {default_path}: {exc}") from exc

        # 2. User overrides
        override_path = self._config_dir / "override.yaml"
        if override_path.is_file():
            try:
                overrides = self._load_yaml(override_path)
                raw = _deep_merge(raw, overrides)
            except OSError as exc:
                raise ConfigError(f"Cannot read overrides file: {override_path}: {exc}") from exc

        # 3. Validate via pydantic (env vars are applied automatically)
        return GlobalConfig(**raw)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _load_yaml(path: Path) -> dict[str, Any]:
        """Load a YAML file and return a plain dict."""
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else {}
