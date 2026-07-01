"""Kasra L3 Rule Engine — Hook registry.

The :class:`HookRegistry` manages a collection of ``Hook`` instances and
fires them at the appropriate lifecycle points.  Pipelines call the
dispatch methods; hook implementations are decoupled from pipeline logic.
"""

from __future__ import annotations

import logging
from typing import Any

from kasra.hooks.base import Hook
from kasra.models.context import RequestContext
from kasra.models.result import AggregatedResult, DetectionResult

logger = logging.getLogger("kasra.hooks")


class HookRegistry:
    """Manages hook registration and dispatch.

    Usage::

        registry = HookRegistry()
        registry.register(MyCustomHook())

        # Later, in the pipeline:
        registry.before_detect(content, context)
    """

    def __init__(self) -> None:
        self._hooks: list[Hook] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, hook: Hook) -> None:
        """Register a hook instance.

        Args:
            hook: A ``Hook`` subclass instance.
        """
        self._hooks.append(hook)

    def unregister(self, hook: Hook) -> None:
        """Remove a previously registered hook."""
        self._hooks.remove(hook)

    def clear(self) -> None:
        """Remove all registered hooks."""
        self._hooks.clear()

    @property
    def hooks(self) -> list[Hook]:
        """Return a snapshot of registered hooks."""
        return list(self._hooks)

    @property
    def count(self) -> int:
        return len(self._hooks)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def before_detect(self, content: str, context: RequestContext | None = None) -> None:
        self._dispatch("before_detect", content=content, context=context)

    def after_detect(self, result: AggregatedResult, context: RequestContext | None = None) -> None:
        self._dispatch("after_detect", result=result, context=context)

    def before_rule(self, rule_id: str, content: str, context: RequestContext | None = None) -> None:
        self._dispatch("before_rule", rule_id=rule_id, content=content, context=context)

    def after_rule(self, result: DetectionResult, context: RequestContext | None = None) -> None:
        self._dispatch("after_rule", result=result, context=context)

    def before_action(self, action_type: str, content: str, context: RequestContext | None = None) -> None:
        self._dispatch("before_action", action_type=action_type, content=content, context=context)

    def after_action(self, action_type: str, content: str | None, context: RequestContext | None = None) -> None:
        self._dispatch("after_action", action_type=action_type, content=content, context=context)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _dispatch(self, method_name: str, **kwargs: Any) -> None:
        """Call a lifecycle method on all registered hooks.

        Exceptions from individual hooks are caught and logged so that a
        failing hook does not disrupt the pipeline or other hooks.
        """
        for hook in self._hooks:
            try:
                method = getattr(hook, method_name, None)
                if method is not None:
                    method(**kwargs)
            except Exception:
                logger.exception(
                    "Hook %s failed on %s", hook.name, method_name
                )
