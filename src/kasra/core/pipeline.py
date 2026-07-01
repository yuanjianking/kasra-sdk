"""Kasra L3 Rule Engine — Abstract detection pipeline.

The :class:`DetectionPipeline` implements the template method pattern
for all four pipeline types (input, output, batch, behavior).

Subclasses override:
  - :meth:`get_rules` — which rules to run.
  - :meth:`get_context` — how to build the request context.
  - :meth:`finalize` — post-processing before returning the result.

The base class handles:
  - Optional content preprocessing (normalization).
  - Rule execution via ``RuleRunner``.
  - Result aggregation via ``AggregatedResult``.
  - Action execution via ``ActionRegistry``.
  - Timing and error capture.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from kasra.actions.base import ActionRegistry
from kasra.actions.block import BlockAction
from kasra.actions.clean import CleanAction
from kasra.actions.redact import RedactAction
from kasra.actions.truncate import TruncateAction
from kasra.actions.warn import WarnAction
from kasra.actions.soft_allow import SoftAllowAction
from kasra.actions.dynamic import DynamicAction
from kasra.analyzers.base import AnalyzerPipeline
from kasra.analyzers.context import AnalysisContext, EvidenceItem
from kasra.core.registry import RuleRegistry
from kasra.core.runner import RuleRunner
from kasra.hooks.registry import HookRegistry
from kasra.models.context import RequestContext
from kasra.models.enums import ActionType, Stage
from kasra.models.result import AggregatedResult
from kasra.models.rule import RuleDefinition
from kasra.preprocessing.normalizer import ContentNormalizer
from kasra.utils.time import timer


class DetectionPipeline(ABC):
    """Abstract base for all detection pipelines.

    Usage::

        class InputDetectionPipeline(DetectionPipeline):
            def get_rules(self) -> list[RuleDefinition]:
                return self._registry.get_rules_for_stage("input")
    """

    def __init__(
        self,
        registry: RuleRegistry,
        runner: RuleRunner,
        action_registry: ActionRegistry | None = None,
        normalizer: ContentNormalizer | None = None,
        analyzer_pipeline: AnalyzerPipeline | None = None,
        hook_registry: HookRegistry | None = None,
    ) -> None:
        self._registry = registry
        self._runner = runner
        self._normalizer = normalizer or ContentNormalizer()
        self._action_registry = action_registry or self._default_action_registry()
        self._analyzer_pipeline = analyzer_pipeline or AnalyzerPipeline.create_default()
        self._hook_registry = hook_registry or HookRegistry()

    # ------------------------------------------------------------------
    # Subclass hooks
    # ------------------------------------------------------------------

    @abstractmethod
    def get_rules(self) -> list[RuleDefinition]:
        """Return the list of rules to evaluate for this pipeline stage."""
        ...

    def get_context(self, **kwargs: Any) -> RequestContext:
        """Build a ``RequestContext`` from keyword arguments.

        Override to inject additional context (user, session, metadata).
        """
        return RequestContext(**kwargs)

    def finalize(
        self,
        aggregated: AggregatedResult,
        action_result: Any,
    ) -> AggregatedResult:
        """Post-process the aggregated result before returning.

        Override to attach additional metadata or transform the result.
        """
        return aggregated

    # ------------------------------------------------------------------
    # Template method
    # ------------------------------------------------------------------

    def run(
        self,
        content: str,
        preprocess: bool = True,
        **context_kwargs: Any,
    ) -> AggregatedResult:
        """Execute the full detection pipeline.

        Template method steps:
          1. Preprocess (normalize) content.
          2. Build request context.
          3. Retrieve rules for this stage.
          4. Run each rule against the content.
          5. Aggregate results.
          6. Execute the action prescribed by the aggregate.
          7. Finalize and return.

        Args:
            content: The text content to evaluate.
            preprocess: Whether to apply normalization.
            **context_kwargs: Additional keyword arguments for the context.

        Returns:
            An ``AggregatedResult`` with all findings and action outcome.
        """
        with timer() as t:
            # 1. Preprocess
            if preprocess:
                content = self.preprocess(content)

            # 1b. Build request context
            context = self.get_context(**context_kwargs)

            # 1c. Plugin hooks: before_detect
            self._hook_registry.before_detect(content, context)

            # 2. Layer 2: Run analyzer pipeline (syntactic analysis)
            analysis_context = self._analyzer_pipeline.execute(content)

            # 3. Rules
            rules = self.get_rules()
            if not rules:
                result = AggregatedResult(
                    overall_action=ActionType.WARN,
                    overall_severity=self._default_severity(),
                    execution_time_ms=0.0,
                )
                self._hook_registry.after_detect(result, context)
                return result

            # 4. Run rules (with Layer 2 context for language/code-block info)
            detection_results = []
            for rule in rules:
                self._hook_registry.before_rule(rule.id, content, context)
                dr = self._runner.run_rule(
                    content, rule,
                    analysis_context=analysis_context,
                )
                self._hook_registry.after_rule(dr, context)
                detection_results.append(dr)

            # 5. Aggregate (with Layer 4 cross-rule correlation)
            aggregated = self._aggregate(detection_results, rules, analysis_context)

            # 6. Execute action
            action_result = self._execute_action(content, aggregated, context)

            # Apply action outcome to aggregated result
            if action_result is not None:
                if action_result.blocked:
                    aggregated.blocked = True
                    aggregated.overall_action = ActionType.BLOCK
                if action_result.truncated:
                    aggregated.truncated = True

        aggregated.execution_time_ms = round(t.elapsed_ms, 2)

        # 7. Finalize
        aggregated = self.finalize(aggregated, action_result)

        # 7b. Plugin hooks: after_detect
        self._hook_registry.after_detect(aggregated, context)

        return aggregated

    # ------------------------------------------------------------------
    # Default implementations
    # ------------------------------------------------------------------

    def preprocess(self, content: str) -> str:
        """Apply content normalization.

        Can be overridden to skip or extend normalization.
        """
        return self._normalizer.normalize(content)

    def _aggregate(
        self,
        results: list[DetectionResult],
        rules: list[RuleDefinition] | None = None,
        analysis_context: AnalysisContext | None = None,
    ) -> AggregatedResult:
        """Combine a list of DetectionResult into one AggregatedResult.

        When *rules* and *analysis_context* are provided, Layer 4
        cross-rule correlation runs as a post-processing step.
        """
        aggregated = AggregatedResult(
            overall_action=ActionType.WARN,
            overall_severity=self._default_severity(),
            analysis_context=analysis_context,
        )
        for result in results:
            aggregated.add_result(result)

        # Layer 4: Cross-rule correlation
        if rules and analysis_context and aggregated.triggered_rules:
            try:
                from kasra.analyzers.correlator import CrossRuleCorrelator
                correlator = CrossRuleCorrelator()
                correlator.correlate(aggregated, rules, analysis_context)
            except Exception:
                import logging
                logging.getLogger("kasra.pipeline").exception(
                    "Cross-rule correlation failed"
                )

        # Wire up dead config flags: admin_alert, compliance_audit, gdpr_audit
        rule_map = {r.id: r for r in (rules or [])}
        for dr in aggregated.triggered_rules:
            rule_def = rule_map.get(dr.rule_id)
            if not rule_def:
                continue
            if rule_def.config.admin_alert:
                aggregated.admin_alert = True
            if rule_def.config.compliance_audit:
                aggregated.compliance_audit = True
            if rule_def.config.gdpr_audit:
                aggregated.gdpr_audit = True

            # Wire up modifier_rule / severity_reduction
            if rule_def.config.modifier_rule and rule_def.config.severity_reduction:
                for target_rule_id, reduced_sev_str in rule_def.config.severity_reduction.items():
                    aggregated.metadata.setdefault("severity_reductions", {})
                    aggregated.metadata["severity_reductions"][target_rule_id] = reduced_sev_str

            # Wire up flags passthrough
            if rule_def.config.flags:
                for k, v in rule_def.config.flags.items():
                    if k not in aggregated.metadata:
                        aggregated.metadata[k] = v

        return aggregated

    def _execute_action(
        self,
        content: str,
        aggregated: AggregatedResult,
        context: RequestContext | None = None,
    ) -> Any:
        """Look up and run the action executor for the overall action."""
        try:
            executor = self._action_registry.get(aggregated.overall_action)
            return executor.apply(content, aggregated, context)
        except KeyError:
            return None

    @staticmethod
    def _default_severity() -> "Severity":
        """Return a ``Severity`` value for empty-result defaults."""
        from kasra.models.enums import Severity
        return Severity.P2

    @staticmethod
    def _default_action_registry() -> ActionRegistry:
        """Create and populate the standard action registry."""
        registry = ActionRegistry()
        registry.register(ActionType.BLOCK, BlockAction())
        registry.register(ActionType.WARN, WarnAction())
        registry.register(ActionType.REDACT, RedactAction())
        registry.register(ActionType.CLEAN, CleanAction())
        registry.register(ActionType.TRUNCATE, TruncateAction())
        registry.register(ActionType.SOFT_ALLOW, SoftAllowAction())
        registry.register(ActionType.DYNAMIC, DynamicAction())
        return registry
