"""Kasra L3 Rule Engine — Clean action executor.

Normalizes/cleans problematic characters from the content without full
redaction.  Uses the shared text utilities (``utils.text``) for Unicode
normalization, invisible-character stripping, and control-code removal.
"""

from __future__ import annotations

import unicodedata

from kasra.actions.base import ActionExecutor, ActionResult
from kasra.models.context import RequestContext
from kasra.models.enums import ActionType
from kasra.models.result import AggregatedResult
from kasra.utils.text import strip_control, strip_invisible


class CleanAction(ActionExecutor):
    """Clean action — normalises content by stripping problematic characters."""

    action_type = ActionType.CLEAN

    def apply(
        self,
        content: str,
        result: AggregatedResult,
        context: RequestContext | None = None,
    ) -> ActionResult:
        # 1. Unicode NFKC normalization (compatibility form — more aggressive
        #    than NFC, collapsing e.g. fullwidth letters → ASCII)
        cleaned = unicodedata.normalize("NFKC", content)

        # 2. Strip invisible / zero-width characters (shared 31-char set)
        cleaned = strip_invisible(cleaned)

        # 3. Remove control characters except \n \t \r
        cleaned = strip_control(cleaned)

        return ActionResult(
            action=ActionType.CLEAN,
            content=cleaned,
            blocked=False,
            warnings=result.warnings,
        )
