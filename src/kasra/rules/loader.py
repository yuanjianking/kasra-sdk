"""Kasra L3 Rule Engine — Rule loader.

Reads rule definition JSON bundles, validates them via Pydantic,
and produces lists of RuleDefinition objects.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import orjson

from kasra.exceptions.errors import RuleLoadError
from kasra.models.rule import RuleBundle, RuleDefinition


class RuleLoader:
    """Loads rule definitions from JSON bundle files.

    The loader reads the bundle format:
        { "bundle": { "series": "I", "name": "...", "version": "...", "total": 57 },
          "rules": [ { "id": "I-01", ... }, ... ] }

    Supports loading from:
      - A single JSON file
      - A directory of JSON files (all *-rules.json files)
      - A specific list of file paths
      - Raw JSON strings (for testing)
    """

    def __init__(self, rules_dir: str | os.PathLike | None = None) -> None:
        """Initialise the loader.

        Args:
            rules_dir: Optional base directory for rule JSON files.
                       If ``None``, the directory is auto-detected via
                       :func:`kasra.utils.package.find_data_dir`.
        """
        self._rules_dir: Path
        if rules_dir is not None:
            self._rules_dir = Path(rules_dir)
        else:
            from kasra.utils.package import find_data_dir
            self._rules_dir = find_data_dir("rules")
        self._rules_dir = self._rules_dir.resolve()

    @property
    def rules_dir(self) -> Path:
        """The directory the loader searches for rule JSON files."""
        return self._rules_dir

    # ------------------------------------------------------------------
    # Public load helpers
    # ------------------------------------------------------------------

    def load_all(self) -> list[RuleDefinition]:
        """Load all rule JSON files from the configured rules directory.

        Returns:
            A flat list of all RuleDefinition objects found.

        Raises:
            RuleLoadError: If the rules directory does not exist.
        """
        dir_path = self._rules_dir
        if not dir_path.is_dir():
            raise RuleLoadError(f"Rules directory not found: {dir_path}")

        all_rules: list[RuleDefinition] = []
        errors: list[str] = []

        for entry in sorted(dir_path.iterdir()):
            if entry.suffix.lower() != ".json":
                continue
            # Skip non-bundle files (e.g. test fixtures)
            if entry.stem.startswith("_") or entry.stem.startswith("."):
                continue
            try:
                rules = self.load_file(str(entry))
                all_rules.extend(rules)
            except RuleLoadError as exc:
                errors.append(str(exc))

        if errors:
            import warnings
            warnings.warn(f"RuleLoader encountered errors:\n" + "\n".join(errors))

        return all_rules

    def load_file(self, path: str | os.PathLike) -> list[RuleDefinition]:
        """Load rules from a single JSON bundle file.

        Args:
            path: Path to the JSON rule bundle file.

        Returns:
            A list of RuleDefinition objects from the bundle.

        Raises:
            RuleLoadError: If the file cannot be read, parsed, or validated.
        """
        resolved = Path(path)
        if not resolved.is_absolute():
            # Try relative to CWD first, then relative to rules_dir
            cwd_candidate = resolved.resolve()
            if cwd_candidate.exists():
                resolved = cwd_candidate
            else:
                resolved = (self._rules_dir / resolved).resolve()

        if not resolved.exists():
            raise RuleLoadError(f"Rule file not found: {resolved}")
        if not resolved.is_file():
            raise RuleLoadError(f"Not a file: {resolved}")

        try:
            raw = resolved.read_bytes()
            data = orjson.loads(raw)
        except orjson.JSONDecodeError as exc:
            raise RuleLoadError(f"Invalid JSON in {resolved}: {exc}") from exc
        except OSError as exc:
            raise RuleLoadError(f"Cannot read {resolved}: {exc}") from exc

        return self._parse_bundle(data, str(resolved))

    def load_json(self, json_str: str, source: str = "<string>") -> list[RuleDefinition]:
        """Load rules from a raw JSON string (useful for testing).

        Args:
            json_str: JSON string conforming to the bundle schema.
            source: Source label for error messages.

        Returns:
            A list of RuleDefinition objects.
        """
        try:
            data = orjson.loads(json_str)
        except orjson.JSONDecodeError as exc:
            raise RuleLoadError(f"Invalid JSON from {source}: {exc}") from exc

        return self._parse_bundle(data, source)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_bundle(self, data: dict[str, Any], source: str) -> list[RuleDefinition]:
        """Validate and parse a bundle dict into RuleDefinition objects."""
        try:
            bundle = RuleBundle(**data)
        except Exception as exc:
            raise RuleLoadError(f"Validation error in {source}: {exc}") from exc

        return bundle.rules
