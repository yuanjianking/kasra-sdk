"""Kasra L3 Rule Engine — Audit event exporters.

Exporters write formatted audit events to various destinations:
  - Console (stdout / stderr)
  - File (JSONL)
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

from kasra.audit.formatters import AuditFormatter, JSONLFormatter
from kasra.exceptions.errors import AuditError
from kasra.models.events import AuditEvent

logger = logging.getLogger("kasra.audit")


class AuditExporter:
    """Base class for audit event exporters."""

    def export(self, event: AuditEvent) -> None:
        """Write a single formatted event to the destination.

        Args:
            event: The audit event to export.

        Raises:
            AuditError: If writing fails.
        """
        raise NotImplementedError

    def flush(self) -> None:
        """Flush any buffered output.

        Default implementation is a no-op.
        """

    def close(self) -> None:
        """Release resources held by the exporter.

        Default implementation calls ``flush()``.
        """
        self.flush()


class ConsoleExporter(AuditExporter):
    """Exports audit events to stdout (or stderr) as JSONL lines."""

    def __init__(
        self,
        formatter: AuditFormatter | None = None,
        stream: str = "stderr",
    ) -> None:
        self._formatter = formatter or JSONLFormatter()
        self._stream_name = stream
        self._stream: Any = sys.stderr if stream == "stderr" else sys.stdout

    def export(self, event: AuditEvent) -> None:
        try:
            line = self._formatter.format(event)
            print(line, file=self._stream, flush=True)
        except OSError as exc:
            raise AuditError(f"Console export failed: {exc}") from exc


class FileExporter(AuditExporter):
    """Exports audit events to a JSONL file.

    The file is opened in append mode.  If the directory does not exist
    it is created automatically.
    """

    def __init__(
        self,
        path: str | os.PathLike,
        formatter: AuditFormatter | None = None,
    ) -> None:
        self._path = Path(path)
        self._formatter = formatter or JSONLFormatter()
        self._fh: Any = None

    def _ensure_open(self) -> None:
        if self._fh is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self._path.open("a", encoding="utf-8")

    def export(self, event: AuditEvent) -> None:
        try:
            self._ensure_open()
            line = self._formatter.format(event)
            self._fh.write(line + "\n")
            self._fh.flush()
        except OSError as exc:
            raise AuditError(f"File export failed: {exc}") from exc

    def flush(self) -> None:
        if self._fh is not None:
            self._fh.flush()

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None
