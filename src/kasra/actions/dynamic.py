"""Kasra L3 Rule Engine — Dynamic action executor.

The dynamic executor delegates to other executors based on runtime
context: suspicion score, rule severity, and whether block was
requested.

Decision logic:
  1. If the aggregated result has P0 severity → delegate to BlockAction.
  2. If the request context has a high suspicion score (>50) → delegate
     to BlockAction (treat as session-level attack).
  3. If any redact spans exist → delegate to RedactAction.
  4. If there are warnings but no block/redact → delegate to WarnAction.
  5. Otherwise → WarnAction (passthrough).
"""

from __future__ import annotations

from kasra.actions.base import ActionExecutor, ActionResult
from kasra.actions.block import BlockAction
from kasra.actions.redact import RedactAction
from kasra.actions.warn import WarnAction
from kasra.models.enums import ActionType, Severity
from kasra.models.result import AggregatedResult
from kasra.models.context import RequestContext


class DynamicAction(ActionExecutor):
    """Dynamic action — decides at runtime based on context."""

    action_type = ActionType.DYNAMIC

    def __init__(self) -> None:
        self._block = BlockAction()
        self._redact = RedactAction()
        self._warn = WarnAction()

    def apply(
        self,
        content: str,
        result: AggregatedResult,
        context: RequestContext | None = None,
    ) -> ActionResult:
        # P0 + block → block unconditionally
        if result.blocked:
            return self._block.apply(content, result, context)

        # High suspicion score → escalate to block
        if context is not None and context.suspicion_score > 50:
            return self._block.apply(content, result, context)

        # Redact spans → redact
        if result.redact_spans:
            return self._redact.apply(content, result, context)

        # Warnings → warn
        if result.warnings:
            return self._warn.apply(content, result, context)

        # Default passthrough
        return self._warn.apply(content, result, context)
