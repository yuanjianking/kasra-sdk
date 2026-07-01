"""Kasra L3 Rule Engine — Batch file-scan pipeline.

The batch pipeline scans files and directories for rule violations
(credential leaks, hardcoded secrets, policy violations in code, etc.).

It handles:
  - File reading with size limits and encoding detection.
  - Exclusion pattern matching (gitignore-style).
  - Per-file aggregation of results.
  - Directory walking with parallel file scanning.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Any

from kasra.core.pipeline import DetectionPipeline
from kasra.models.context import FileContext
from kasra.models.enums import Stage
from kasra.models.result import AggregatedResult
from kasra.models.rule import RuleDefinition
from kasra.preprocessing.normalizer import ContentNormalizer


class BatchScanPipeline(DetectionPipeline):
    """Batch file-scan pipeline.

    Scans files and directories for rule violations.

    Usage::

        pipeline = BatchScanPipeline(registry, runner)

        # Single file
        result = pipeline.scan_file("config.py")
        # or via the base run() method:
        result = pipeline.run(content="", file_path="config.py")

        # Entire directory
        results = pipeline.scan_directory("./src")
    """

    def __init__(
        self,
        registry: Any,
        runner: Any,
        action_registry: Any | None = None,
        normalizer: ContentNormalizer | None = None,
        max_file_size_mb: int = 10,
        exclude_patterns: list[str] | None = None,
    ) -> None:
        super().__init__(registry, runner, action_registry, normalizer)
        self._max_file_size = max_file_size_mb * 1024 * 1024
        self._exclude_patterns = exclude_patterns or [
            "node_modules/**",
            ".git/**",
            "__pycache__/**",
            "vendor/**",
            "*.min.js",
            "*.pyc",
            "*.egg-info/**",
            ".venv/**",
            "venv/**",
            ".tox/**",
            "*.swp",
            "*.swo",
            ".DS_Store",
        ]

    def get_rules(self) -> list[RuleDefinition]:
        """Return batch-stage + input-stage rules, ordered P0 → P1 → P2.

        Includes input-stage rules so credential / secret detection works
        when scanning files and directories, even before dedicated batch
        rule series (SEC, IAC) are loaded.
        """
        rules = list(self._registry.get_rules_for_stage(Stage.BATCH))
        # Also include input-stage rules — credential scanning in files
        # is the same use case as credential scanning in prompts.
        input_rules = self._registry.get_rules_for_stage(Stage.INPUT)
        seen = {r.id for r in rules}
        for r in input_rules:
            if r.id not in seen:
                rules.append(r)
                seen.add(r.id)
        return rules

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(
        self,
        file_path: str | os.PathLike,
        preprocess: bool = True,
    ) -> AggregatedResult:
        """Scan a single file.

        Args:
            file_path: Path to the file.
            preprocess: Whether to apply content normalization.

        Returns:
            An ``AggregatedResult`` with findings.
        """
        path = Path(file_path)
        if not path.is_file():
            return AggregatedResult(
                metadata={"error": f"File not found: {path}", "file_path": str(path)},
            )

        try:
            content, file_ctx = self._read_file(path)
        except Exception as exc:
            return AggregatedResult(
                metadata={"error": f"Cannot read file: {exc}", "file_path": str(path)},
            )

        context_kwargs = {
            "file_path": str(path),
            "file_size": file_ctx.file_size,
            "mime_type": file_ctx.mime_type or "",
        }
        return self.run(content, preprocess=preprocess, **context_kwargs)

    def scan_directory(
        self,
        dir_path: str | os.PathLike,
        preprocess: bool = True,
    ) -> list[AggregatedResult]:
        """Scan all matching files in a directory.

        Args:
            dir_path: Path to the directory.
            preprocess: Whether to apply normalization.

        Returns:
            A list of ``AggregatedResult`` objects, one per file.
        """
        path = Path(dir_path)
        if not path.is_dir():
            return []

        results: list[AggregatedResult] = []
        for file_entry in sorted(path.rglob("*")):
            if not file_entry.is_file():
                continue
            if self._is_excluded(str(file_entry)):
                continue
            if file_entry.stat().st_size > self._max_file_size:
                continue

            result = self.scan_file(file_entry)
            results.append(result)

        return results

    # ------------------------------------------------------------------
    # Pipeline hook overrides
    # ------------------------------------------------------------------

    def get_context(self, **kwargs: Any) -> Any:
        # batch pipeline doesn't use RequestContext as a traditional context
        from kasra.models.context import RequestContext
        return RequestContext(
            source="batch",
            metadata=kwargs,
        )

    def finalize(
        self,
        aggregated: AggregatedResult,
        action_result: Any,
    ) -> AggregatedResult:
        if action_result is not None:
            aggregated.metadata = dict(aggregated.metadata or {})
            if hasattr(action_result, 'content'):
                aggregated.metadata["processed_content"] = action_result.content
        return aggregated

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _read_file(self, path: Path) -> tuple[str, FileContext]:
        """Read and decode a file, returning its content and context."""
        stat = path.stat()
        raw = path.read_bytes()

        mime = self._guess_mime(path)

        try:
            text = ContentNormalizer.decode_and_normalize(raw)
        except Exception:
            # Binary fallback
            text = raw.decode("utf-8", errors="replace")

        file_ctx = FileContext(
            file_path=str(path),
            file_size=stat.st_size,
            mime_type=mime,
            content=text,
            is_binary="binary" in mime,
        )

        return text, file_ctx

    def _is_excluded(self, file_path: str) -> bool:
        """Check if a path matches any exclusion pattern."""
        rel = file_path.lstrip("/")
        for pattern in self._exclude_patterns:
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, f"**/{pattern}"):
                return True
        return False

    @staticmethod
    def _guess_mime(path: Path) -> str:
        """Guess MIME type from file extension."""
        ext = path.suffix.lower()
        mime_map: dict[str, str] = {
            ".py": "text/x-python",
            ".js": "text/javascript",
            ".ts": "text/typescript",
            ".jsx": "text/jsx",
            ".tsx": "text/typescript",
            ".go": "text/x-go",
            ".rs": "text/x-rust",
            ".java": "text/x-java",
            ".c": "text/x-c",
            ".cpp": "text/x-c++",
            ".h": "text/x-c-header",
            ".cs": "text/x-csharp",
            ".rb": "text/x-ruby",
            ".php": "text/x-php",
            ".swift": "text/x-swift",
            ".kt": "text/x-kotlin",
            ".scala": "text/x-scala",
            ".sh": "text/x-shellscript",
            ".bash": "text/x-shellscript",
            ".zsh": "text/x-shellscript",
            ".yaml": "text/x-yaml",
            ".yml": "text/x-yaml",
            ".json": "application/json",
            ".xml": "application/xml",
            ".html": "text/html",
            ".htm": "text/html",
            ".css": "text/css",
            ".scss": "text/x-scss",
            ".md": "text/markdown",
            ".rst": "text/x-rst",
            ".txt": "text/plain",
            ".csv": "text/csv",
            ".env": "text/plain",
            ".conf": "text/plain",
            ".cfg": "text/plain",
            ".ini": "text/plain",
            ".toml": "text/x-toml",
            ".sql": "text/x-sql",
            ".dockerfile": "text/x-dockerfile",
            ".proto": "text/x-protobuf",
        }
        return mime_map.get(ext, "application/octet-stream")
