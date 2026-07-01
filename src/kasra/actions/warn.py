"""Kasra L3 Rule Engine — Warn action executor.

Allows the content through unchanged but attaches warning messages
to the result.
"""

from __future__ import annotations

from kasra.actions.base import ActionExecutor, ActionResult
from kasra.models.enums import ActionType
from kasra.models.result import AggregatedResult
from kasra.models.context import RequestContext


class WarnAction(ActionExecutor):
    """Warn action — content passes through with warnings attached."""

    action_type = ActionType.WARN

    def apply(
        self,
        content: str,
        result: AggregatedResult,
        context: RequestContext | None = None,
    ) -> ActionResult:
        return ActionResult(
            action=ActionType.WARN,
            content=content,
            blocked=False,
            warnings=result.warnings,
        )
