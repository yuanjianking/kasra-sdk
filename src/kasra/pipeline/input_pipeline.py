"""Kasra L3 Rule Engine — Input detection pipeline.

The input pipeline runs **before** content reaches the AI model.  It
evaluates all input-stage rules and can block, warn, redact, or clean
the content.

This is the most security-critical pipeline — malicious prompts,
credential leaks, and injection attacks are caught here.
"""

from __future__ import annotations

from typing import Any

from kasra.core.pipeline import DetectionPipeline
from kasra.models.enums import Stage
from kasra.models.rule import RuleDefinition
from kasra.models.result import AggregatedResult


class InputDetectionPipeline(DetectionPipeline):
    """Real-time input detection pipeline.

    Evaluates all input-stage rules against user-submitted content
    before it reaches the AI model.

    Usage::

        pipeline = InputDetectionPipeline(registry, runner)
        result = pipeline.run("my password is secret123")
    """

    def get_rules(self) -> list[RuleDefinition]:
        """Return all enabled input-stage rules, ordered P0 → P1 → P2."""
        return self._registry.get_rules_for_stage(Stage.INPUT)

    def finalize(
        self,
        aggregated: AggregatedResult,
        action_result: Any,
    ) -> AggregatedResult:
        """Attach input-specific metadata."""
        # If the action produced modified content, store it in the result
        # metadata for the caller
        if action_result is not None:
            aggregated.metadata = {
                "processed_content": action_result.content,
                "action_taken": action_result.action.value if hasattr(action_result, 'action') else None,
            }
        return aggregated
