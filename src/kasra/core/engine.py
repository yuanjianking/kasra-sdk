"""Kasra Rule Engine — Public API.

The :class:`RuleEngine` is the single entry point for all SDK consumers::

    from kasra import RuleEngine

    engine = RuleEngine()
    engine.load_rules()

    result = engine.detect_input("my password is secret123")
    if result.blocked:
        print("Content was blocked")
    elif result.warnings:
        print("Warnings:", result.warnings)
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from kasra.actions.base import ActionRegistry
from kasra.audit.logger import AuditLogger
from kasra.audit.exporters import ConsoleExporter, FileExporter
from kasra.config.global_config import GlobalConfig
from kasra.config.loader import ConfigLoader
from kasra.core.pipeline import DetectionPipeline
from kasra.core.registry import RuleRegistry
from kasra.core.runner import RuleRunner
from kasra.hooks.builtin import MetricsCollector
from kasra.hooks.registry import HookRegistry
from kasra.models.context import FileContext, RequestContext
from kasra.models.enums import Stage
from kasra.models.result import AggregatedResult, DetectionResult
from kasra.models.rule import RuleDefinition
from kasra.rules.loader import RuleLoader
from kasra.rules.store import RuleStore
from kasra.pipeline.input_pipeline import InputDetectionPipeline
from kasra.pipeline.output_pipeline import OutputDetectionPipeline
from kasra.pipeline.behavior_pipeline import BehaviorDetectionPipeline
from kasra.scanner import CodeReviewScanner
from kasra.scanner.models import CodeReviewResult


class RuleEngine:
    """Top-level Kasra Rule Engine.

    Manages the lifecycle:
      1. **Configuration** — loaded from YAML + env vars via ``GlobalConfig``.
      2. **Rule loading** — reads JSON rule bundles from disk.
      3. **Indexing** — builds severity/stage indexes via ``RuleRegistry``.
      4. **Detection** — dispatches to the appropriate pipeline per stage.
      5. **Audit** — automatically logs all detection results.

    Usage::

        engine = RuleEngine()
        engine.load_rules()                     # load all rules from default dir
        result = engine.detect_input(text)      # run input pipeline
        engine.stop()                           # flush audit logs
    """

    def __init__(
        self,
        config: GlobalConfig | None = None,
        rules_dir: str | os.PathLike | None = None,
        config_dir: str | os.PathLike | None = None,
    ) -> None:
        self._config = config or ConfigLoader(config_dir).load()

        # Core components
        self._loader = RuleLoader(rules_dir)
        self._store = RuleStore()
        self._registry = RuleRegistry(self._store)
        self._runner = RuleRunner()
        self._action_registry = ActionRegistry()

        # Populate action registry
        self._init_action_registry()

        # Audit logger
        self._audit_logger: AuditLogger | None = None
        self._audit_lock = threading.Lock()

        # Plugin hook registry (built-in MetricsCollector registered by default)
        self._hook_registry = HookRegistry()
        self._hook_registry.register(MetricsCollector())

        # Pipeline instances (created lazily)
        self._input_pipeline: InputDetectionPipeline | None = None
        self._output_pipeline: OutputDetectionPipeline | None = None
        # batch_pipeline removed — use CodeReviewScanner for code review,
        # or Path.read_text() + detect_input() to scan file contents.
        self._behavior_pipeline: BehaviorDetectionPipeline | None = None
        self._code_review_scanner: CodeReviewScanner | None = None

        self._loaded = False
        self._rule_count = 0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def config(self) -> GlobalConfig:
        return self._config

    @property
    def store(self) -> RuleStore:
        return self._store

    @property
    def registry(self) -> RuleRegistry:
        return self._registry

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def rule_count(self) -> int:
        return self._rule_count

    @property
    def audit_logger(self) -> AuditLogger | None:
        """Return the current ``AuditLogger``, if audit logging is enabled.

        Returns ``None`` when ``config.audit.enabled`` is ``False``.
        """
        return self._audit_logger

    @property
    def hook_registry(self) -> HookRegistry:
        """Return the plugin hook registry.

        Register custom hooks via :meth:`register_hook`.
        """
        return self._hook_registry

    def register_hook(self, hook: Hook) -> None:
        """Register a plugin hook.

        Args:
            hook: A ``Hook`` subclass instance.

        The hook will receive lifecycle callbacks for all subsequent
        detections.  Built-in ``MetricsCollector`` is pre-registered.
        """
        from kasra.hooks.base import Hook
        self._hook_registry.register(hook)

    # ------------------------------------------------------------------
    # Audit lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the audit logger (background worker).

        Called automatically on first detection — explicit call is
        only needed if you want to guarantee the worker is running
        before the first detection completes.
        """
        if not self._config.audit.enabled:
            return
        logger = self._get_or_create_audit_logger()
        logger.start()

    def stop(self) -> None:
        """Stop the audit logger and flush all pending events.

        Always call this at application shutdown to avoid data loss.
        """
        if self._audit_logger is not None:
            self._audit_logger.stop()

    def _get_or_create_audit_logger(self) -> AuditLogger:
        """Create the ``AuditLogger`` on first access (lazy)."""
        if self._audit_logger is None:
            with self._audit_lock:
                if self._audit_logger is None:
                    ac = self._config.audit
                    exporters: list = []
                    if ac.log_to_console:
                        exporters.append(ConsoleExporter())
                    if ac.jsonl_path:
                        exporters.append(FileExporter(path=ac.jsonl_path))
                    self._audit_logger = AuditLogger(
                        exporters=exporters or None,
                        max_queue_size=ac.max_queue_size,
                        batch_write_interval=ac.batch_write_interval_seconds,
                    )
                    # Start the background worker immediately
                    self._audit_logger.start()
        return self._audit_logger

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def load_rules(self, path: str | os.PathLike | None = None) -> int:
        """Load rule definitions from JSON bundle file(s).

        Args:
            path: Optional path to a specific JSON rule file.
                  If ``None``, loads all rules from the configured rules directory.

        Returns:
            The number of rules loaded.

        Raises:
            RuleLoadError: If a rule file cannot be read or validated.
        """
        if path is not None:
            rules = self._loader.load_file(path)
        else:
            rules = self._loader.load_all()

        self._store.bulk_replace(rules)
        self._registry.rebuild()
        self._loaded = True
        self._rule_count = self._store.count()

        # Validate all rules (warnings only)
        for rule in rules:
            patterns = rule.detection.patterns
            if not patterns and not rule.config.no_pattern_match:
                # Rules with no patterns and no config-only flag — likely misconfigured
                logger = __import__("logging").getLogger("kasra.engine")
                logger.debug("Rule %s has no detection patterns", rule.id)

        return self._rule_count

    def reload_rules(self) -> int:
        """Reload all rules from the configured rules directory.

        Useful for hot-reload in development.
        """
        self._loaded = False
        return self.load_rules()

    # ------------------------------------------------------------------
    # Detection pipelines
    # ------------------------------------------------------------------

    def detect_input(
        self,
        content: str,
        preprocess: bool = True,
        **context_kwargs: Any,
    ) -> AggregatedResult:
        """Run the input detection pipeline.

        Evaluates all input-stage rules against *content* and returns an
        aggregated result with the appropriate action.  If audit logging
        is enabled the result is automatically recorded.

        Args:
            content: The text content to evaluate.
            preprocess: Whether to apply content normalization.
            **context_kwargs: Additional request context fields
                (``user_id``, ``session_id``, ``request_id``, etc.).

        Returns:
            An ``AggregatedResult`` describing all findings.

        Raises:
            TypeError: If *content* is not a string.
        """
        if not isinstance(content, str):
            raise TypeError(f"content must be str, got {type(content).__name__}")
        pipeline = self._get_input_pipeline()
        result = pipeline.run(content, preprocess=preprocess, **context_kwargs)
        self._audit_if_enabled(result, stage="input", **context_kwargs)
        return result

    def detect_output(
        self,
        content: str,
        preprocess: bool = True,
        **context_kwargs: Any,
    ) -> AggregatedResult:
        """Run the output detection pipeline.

        Evaluates all output-stage rules against *content*.
        Results are automatically audited if logging is enabled.

        Args:
            content: The text content to evaluate.
            preprocess: Whether to apply content normalization.
            **context_kwargs: Additional request context fields.

        Returns:
            An ``AggregatedResult`` describing all findings.

        Raises:
            TypeError: If *content* is not a string.
        """
        if not isinstance(content, str):
            raise TypeError(f"content must be str, got {type(content).__name__}")
        pipeline = self._get_output_pipeline()
        result = pipeline.run(content, preprocess=preprocess, **context_kwargs)
        self._audit_if_enabled(result, stage="output", **context_kwargs)
        return result

    def track_behavior(
        self,
        content: str,
        session_id: str,
        **context_kwargs: Any,
    ) -> AggregatedResult:
        """Run the behavior monitoring pipeline.

        Evaluates behavior-stage rules, updates session state, and
        automatically audits the result.

        Args:
            content: The message content.
            session_id: The session identifier for tracking.
            **context_kwargs: Additional context fields.

        Returns:
            An ``AggregatedResult`` describing behavior findings.
        """
        pipeline = self._get_behavior_pipeline()
        result = pipeline.run(
            content,
            preprocess=True,
            session_id=session_id,
            **context_kwargs,
        )
        self._audit_if_enabled(result, stage="behavior", session_id=session_id, **context_kwargs)
        return result

    # ------------------------------------------------------------------
    # Runtime rule control (enable / disable)
    # ------------------------------------------------------------------

    def enable_rule(self, rule_id: str) -> None:
        """Enable a rule at runtime.

        The rule is re-enabled immediately in the pipeline indexes.
        No reload required.

        Args:
            rule_id: The rule ID to enable.

        Raises:
            RuleNotFoundError: If the rule does not exist.
        """
        self._store.set_enabled(rule_id, enabled=True)

    def disable_rule(self, rule_id: str) -> None:
        """Disable a rule at runtime.

        The rule is removed from pipeline queries immediately.
        No reload required.

        Args:
            rule_id: The rule ID to disable.

        Raises:
            RuleNotFoundError: If the rule does not exist.
        """
        self._store.set_enabled(rule_id, enabled=False)

    # ------------------------------------------------------------------
    # Code review (CodeReviewScanner integration)
    # ------------------------------------------------------------------

    def review_code(
        self,
        path: str | os.PathLike,
    ) -> CodeReviewResult:
        """Run a code review security scan on a file or directory.

        Delegates to :class:`CodeReviewScanner` under the hood, loading
        rules from ``_code-review-rules.json`` on first call.

        Args:
            path: Path to a file or directory to scan.

        Returns:
            A ``CodeReviewResult`` containing all findings.
        """
        scanner = self._get_code_review_scanner()
        if not scanner.rules:
            scanner.load_rules()
        return scanner.scan(str(path))

    def get_code_review_rules(self) -> list[dict[str, Any]]:
        """Return the loaded code review rule definitions.

        Returns:
            A list of rule dicts (empty if ``review_code()`` has not
            been called yet).
        """
        scanner = self._get_code_review_scanner()
        if not scanner.rules:
            try:
                scanner.load_rules()
            except FileNotFoundError:
                pass
        return scanner.rules

    def get_code_review_rule_ids(self) -> list[str]:
        """Return the list of loaded code review rule IDs."""
        return [r.get("id", "UNKNOWN") for r in self.get_code_review_rules()]

    def enable_code_review_rule(self, rule_id: str) -> None:
        """Re-enable a code review rule at runtime.

        Args:
            rule_id: The rule ID to enable (e.g. ``"SEC-01"``).

        Raises:
            ValueError: If the rule ID is not found.
        """
        scanner = self._get_code_review_scanner()
        scanner.enable_rule(rule_id)

    def disable_code_review_rule(self, rule_id: str) -> None:
        """Disable a code review rule at runtime.

        The rule will be skipped in subsequent ``review_code()`` calls.

        Args:
            rule_id: The rule ID to disable (e.g. ``"SEC-01"``).

        Raises:
            ValueError: If the rule ID is not found.
        """
        scanner = self._get_code_review_scanner()
        scanner.disable_rule(rule_id)

    @property
    def disabled_code_review_rule_ids(self) -> set[str]:
        """Return the set of currently disabled code review rule IDs."""
        return set(self._get_code_review_scanner().disabled_rule_ids)

    # ------------------------------------------------------------------
    # Direct rule access
    # ------------------------------------------------------------------

    def get_rule(self, rule_id: str) -> RuleDefinition:
        """Get a single rule definition by ID."""
        return self._store.get(rule_id)

    def get_rules(self) -> list[RuleDefinition]:
        """Get all loaded rule definitions."""
        return self._store.all()

    def get_rules_for_stage(self, stage: str | Stage) -> list[RuleDefinition]:
        """Get rules applicable to a given pipeline stage."""
        return self._store.get_enabled_by_stage(stage)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _audit_if_enabled(self, result: AggregatedResult, stage: str, **context_kwargs: Any) -> None:
        """Write audit events if the logger is configured and enabled."""
        if not self._config.audit.enabled:
            return
        if not result.triggered_rules:
            return
        try:
            logger = self._get_or_create_audit_logger()
            logger.log_result(
                result,
                stage=stage,
                user_id=context_kwargs.get("user_id"),
                session_id=context_kwargs.get("session_id"),
                request_id=context_kwargs.get("request_id"),
                source=context_kwargs.get("source", "api"),
            )
        except Exception:
            import logging
            logging.getLogger("kasra.engine").exception("Audit logging failed")

    def _get_input_pipeline(self) -> InputDetectionPipeline:
        if self._input_pipeline is None:
            self._input_pipeline = InputDetectionPipeline(
                registry=self._registry,
                runner=self._runner,
                action_registry=self._action_registry,
                hook_registry=self._hook_registry,
            )
        return self._input_pipeline

    def _get_output_pipeline(self) -> OutputDetectionPipeline:
        if self._output_pipeline is None:
            self._output_pipeline = OutputDetectionPipeline(
                registry=self._registry,
                runner=self._runner,
                action_registry=self._action_registry,
                hook_registry=self._hook_registry,
            )
        return self._output_pipeline

    def _get_behavior_pipeline(self) -> BehaviorDetectionPipeline:
        if self._behavior_pipeline is None:
            self._behavior_pipeline = BehaviorDetectionPipeline(
                registry=self._registry,
                runner=self._runner,
                action_registry=self._action_registry,
                hook_registry=self._hook_registry,
            )
        return self._behavior_pipeline

    def _get_code_review_scanner(self) -> CodeReviewScanner:
        if self._code_review_scanner is None:
            from kasra.utils.package import find_data_dir

            rules_path = find_data_dir("rules") / "_code-review-rules.json"
            self._code_review_scanner = CodeReviewScanner(rules_path=rules_path)
        return self._code_review_scanner

    def _init_action_registry(self) -> None:
        """Register all seven standard action executors."""
        from kasra.actions.block import BlockAction
        from kasra.actions.warn import WarnAction
        from kasra.actions.redact import RedactAction
        from kasra.actions.clean import CleanAction
        from kasra.actions.truncate import TruncateAction
        from kasra.actions.soft_allow import SoftAllowAction
        from kasra.actions.dynamic import DynamicAction
        from kasra.models.enums import ActionType

        self._action_registry.register(ActionType.BLOCK, BlockAction())
        self._action_registry.register(ActionType.WARN, WarnAction())
        self._action_registry.register(ActionType.REDACT, RedactAction())
        self._action_registry.register(ActionType.CLEAN, CleanAction())
        self._action_registry.register(ActionType.TRUNCATE, TruncateAction())
        self._action_registry.register(ActionType.SOFT_ALLOW, SoftAllowAction())
        self._action_registry.register(ActionType.DYNAMIC, DynamicAction())
