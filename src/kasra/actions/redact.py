"""Kasra L3 Rule Engine — Redact action executor.

Replaces matched text spans with a placeholder (``[REDACTED]`` by default).
Spans are applied in reverse position order so that earlier offsets remain
valid after each replacement.
"""

from __future__ import annotations

from kasra.actions.base import ActionExecutor, ActionResult
from kasra.models.enums import ActionType
from kasra.models.result import AggregatedResult, MatchSpan
from kasra.models.context import RequestContext


class RedactAction(ActionExecutor):
    """Redact action — replaces matched content with a placeholder."""

    action_type = ActionType.REDACT

    REDACT_TOKEN = "[REDACTED]"

    def apply(
        self,
        content: str,
        result: AggregatedResult,
        context: RequestContext | None = None,
    ) -> ActionResult:
        redacted = content
        # Apply redactions in reverse order so positions stay valid
        for span in sorted(result.redact_spans, key=lambda s: s.start, reverse=True):
            replacement = span.redacted or self.REDACT_TOKEN
            redacted = redacted[: span.start] + replacement + redacted[span.end :]

        return ActionResult(
            action=ActionType.REDACT,
            content=redacted,
            blocked=False,
            warnings=result.warnings,
            redact_spans=result.redact_spans,
        )
