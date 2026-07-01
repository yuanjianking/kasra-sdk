"""Kasra L3 Rule Engine — Plugin hook base.

Hooks provide extension points for custom behaviour at key moments in
the pipeline lifecycle:

  - ``before_detect`` / ``after_detect`` — around the full detection run.
  - ``before_rule`` / ``after_rule`` — around individual rule execution.
  - ``before_action`` / ``after_action`` — around action execution.

Hooks are **stateless** callables.  Implementations should not maintain
mutable state — use the ``HookRegistry`` for lifecycle management.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from kasra.models.context import RequestContext
from kasra.models.result import AggregatedResult, DetectionResult


class Hook(ABC):
    """Abstract base for all plugin hooks.

    Subclass this and override the relevant lifecycle methods.
    All methods are no-ops by default.
    """

    @property
    def name(self) -> str:
        """Human-readable hook name."""
        return type(self).__name__

    # ------------------------------------------------------------------
    # Pipeline lifecycle
    # ------------------------------------------------------------------

    def before_detect(
        self,
        content: str,
        context: RequestContext | None,
    ) -> None:
        """Called before the detection pipeline runs.

        Args:
            content: The content about to be evaluated.
            context: The request context (may be None).
        """

    def after_detect(
        self,
        result: AggregatedResult,
        context: RequestContext | None,
    ) -> None:
        """Called after the detection pipeline completes.

        Args:
            result: The aggregated detection result.
            context: The request context (may be None).
        """

    # ------------------------------------------------------------------
    # Rule lifecycle
    # ------------------------------------------------------------------

    def before_rule(
        self,
        rule_id: str,
        content: str,
        context: RequestContext | None,
    ) -> None:
        """Called before a single rule is evaluated.

        Args:
            rule_id: The rule ID about to run.
            content: The content being evaluated.
            context: The request context (may be None).
        """

    def after_rule(
        self,
        result: DetectionResult,
        context: RequestContext | None,
    ) -> None:
        """Called after a single rule has been evaluated.

        Args:
            result: The detection result for this rule.
            context: The request context (may be None).
        """

    # ------------------------------------------------------------------
    # Action lifecycle
    # ------------------------------------------------------------------

    def before_action(
        self,
        action_type: str,
        content: str,
        context: RequestContext | None,
    ) -> None:
        """Called before an action is executed.

        Args:
            action_type: The action type being executed (e.g. "block", "warn").
            content: The content being acted upon.
            context: The request context (may be None).
        """

    def after_action(
        self,
        action_type: str,
        content: str | None,
        context: RequestContext | None,
    ) -> None:
        """Called after an action has been executed.

        Args:
            action_type: The action type that was executed.
            content: The (possibly modified) content.
            context: The request context (may be None).
        """
