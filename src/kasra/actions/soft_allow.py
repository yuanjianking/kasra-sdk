"""Kasra L3 Rule Engine — Soft-allow action executor.

Allows the content through unchanged but marks it for audit-only
processing.  The result severity is reduced to P2 (advisory) so that
no blocking or user-visible warnings occur, but the event is still
written to the audit log.
"""

from __future__ import annotations

from kasra.actions.base import ActionExecutor, ActionResult
from kasra.models.enums import ActionType
from kasra.models.result import AggregatedResult
from kasra.models.context import RequestContext


class SoftAllowAction(ActionExecutor):
    """Soft-allow action — content passes through; audit-only."""

    action_type = ActionType.SOFT_ALLOW

    def apply(
        self,
        content: str,
        result: AggregatedResult,
        context: RequestContext | None = None,
    ) -> ActionResult:
        return ActionResult(
            action=ActionType.SOFT_ALLOW,
            content=content,
            blocked=False,
            warnings=result.warnings,
        )
