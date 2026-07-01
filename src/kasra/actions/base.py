"""Kasra L3 Rule Engine — Action executor base.

Every action executor implements :meth:`apply` which receives the original
content and the aggregated detection result, and returns an ``ActionResult``
modelling what should happen to the content.

The :class:`ActionRegistry` maps ``ActionType`` → ``ActionExecutor`` and is
the single point of configuration for available actions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from kasra.models.enums import ActionType
from kasra.models.result import AggregatedResult, MatchSpan
from kasra.models.context import RequestContext


class ActionResult(BaseModel):
    """The result of applying an action to content."""

    action: ActionType = Field(..., description="The action that was applied")
    content: str | None = Field(default=None, description="Modified content (None if blocked)")
    blocked: bool = Field(default=False, description="Whether the content was blocked")
    warnings: list[str] = Field(default_factory=list, description="Warning messages")
    truncated: bool = Field(default=False, description="Whether content was truncated")
    redact_spans: list[MatchSpan] = Field(default_factory=list, description="Redacted spans")


class ActionExecutor(ABC):
    """Abstract base for all action executors.

    An action executor receives the original content plus the aggregated
    detection result and returns an ``ActionResult``.  Implementations
    are stateless singletons.
    """

    @abstractmethod
    def apply(
        self,
        content: str,
        result: AggregatedResult,
        context: RequestContext | None = None,
    ) -> ActionResult:
        """Apply the action to *content* based on *result*.

        Args:
            content: The original content.
            result: Aggregated detection result from running rules.
            context: Optional request context for dynamic decisions.

        Returns:
            An ActionResult describing the outcome.
        """
        ...


# -----------------------------------------------------------------------
# ActionRegistry — maps ActionType -> ActionExecutor
# -----------------------------------------------------------------------

class ActionRegistry:
    """Registry that maps ``ActionType`` values to ``ActionExecutor`` instances.

    All seven standard actions are pre-registered.  Callers can override
    individual entries via :meth:`register`.
    """

    def __init__(self) -> None:
        self._executors: dict[ActionType, ActionExecutor] = {}

    def register(self, action: ActionType, executor: ActionExecutor) -> None:
        """Register or override an executor for *action*."""
        self._executors[action] = executor

    def get(self, action: ActionType) -> ActionExecutor:
        """Return the executor for *action*.

        Raises:
            KeyError: If no executor has been registered for *action*.
        """
        if action not in self._executors:
            raise KeyError(f"No executor registered for action: {action.value}")
        return self._executors[action]

    def all(self) -> dict[ActionType, ActionExecutor]:
        """Return a copy of the full mapping."""
        return dict(self._executors)
