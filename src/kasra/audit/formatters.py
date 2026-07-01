"""Kasra L3 Rule Engine — Audit event formatters.

Formatters convert :class:`AuditEvent` objects into serialisable
representations (dict, JSON, JSONL).
"""

from __future__ import annotations

import json
from typing import Any

from kasra.models.events import AuditEvent


class AuditFormatter:
    """Base class for audit event formatters."""

    def format(self, event: AuditEvent) -> Any:
        """Convert an ``AuditEvent`` to the target representation.

        Args:
            event: The audit event to format.

        Returns:
            The formatted event.
        """
        raise NotImplementedError


class DictFormatter(AuditFormatter):
    """Formats an ``AuditEvent`` as a plain dict."""

    def format(self, event: AuditEvent) -> dict[str, Any]:
        return event.model_dump(mode="json")


class JSONFormatter(AuditFormatter):
    """Formats an ``AuditEvent`` as a compact JSON string."""

    def __init__(self, indent: int | None = None) -> None:
        self._indent = indent

    def format(self, event: AuditEvent) -> str:
        data = event.model_dump(mode="json")
        return json.dumps(data, indent=self._indent, ensure_ascii=False)


class JSONLFormatter(AuditFormatter):
    """Formats an ``AuditEvent`` as a single JSON line (JSONL)."""

    def format(self, event: AuditEvent) -> str:
        data = event.model_dump(mode="json")
        return json.dumps(data, ensure_ascii=False, default=str)
