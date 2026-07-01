"""Kasra L3 Rule Engine — Truncate action executor.

Cuts the content at a configured maximum length (default 1000 characters).
The boundary is adjusted to the nearest line break when possible to avoid
splitting mid-word.
"""

from __future__ import annotations

from kasra.actions.base import ActionExecutor, ActionResult
from kasra.models.context import RequestContext
from kasra.models.enums import ActionType
from kasra.models.result import AggregatedResult
from kasra.utils.text import truncate_at_boundary


class TruncateAction(ActionExecutor):
    """Truncate action — cuts content at a maximum length boundary.

    The truncation point is pushed backward to the nearest ``\\n`` before
    *max_length* to avoid mid-line cuts.  If no line break is found within
    a reasonable window the hard limit is used.
    """

    action_type = ActionType.TRUNCATE

    def __init__(self, max_length: int = 1000, boundary_lookback: int = 200) -> None:
        self._max_length = max_length
        self._boundary_lookback = boundary_lookback

    def apply(
        self,
        content: str,
        result: AggregatedResult,
        context: RequestContext | None = None,
    ) -> ActionResult:
        truncated_text, was_truncated = truncate_at_boundary(
            content,
            max_length=self._max_length,
            boundary_lookback=self._boundary_lookback,
        )

        return ActionResult(
            action=ActionType.TRUNCATE,
            content=truncated_text,
            blocked=False,
            warnings=result.warnings,
            truncated=was_truncated,
        )
