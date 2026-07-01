"""Kasra L3 Rule Engine — Block action executor.

Rejects the content outright. The ``ActionResult.content`` is ``None``
and ``blocked`` is ``True``.
"""

from __future__ import annotations

from kasra.actions.base import ActionExecutor, ActionResult
from kasra.models.enums import ActionType
from kasra.models.result import AggregatedResult
from kasra.models.context import RequestContext


class BlockAction(ActionExecutor):
    """Block action — content is rejected and never reaches the AI."""

    action_type = ActionType.BLOCK

    def apply(
        self,
        content: str,
        result: AggregatedResult,
        context: RequestContext | None = None,
    ) -> ActionResult:
        return ActionResult(
            action=ActionType.BLOCK,
            content=None,
            blocked=True,
            warnings=result.warnings,
        )
