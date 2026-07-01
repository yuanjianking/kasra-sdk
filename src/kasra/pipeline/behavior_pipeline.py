"""Kasra L3 Rule Engine — Behavior monitoring pipeline.

The behavior pipeline tracks **session-level** patterns that span
multiple turns, such as:
  - Split attacks (distributing a malicious prompt across turns)
  - Probing / recon behaviour (escalating suspicion score)
  - Cumulative policy violations
  - Session pollution detection

Unlike the input/output pipelines which evaluate single requests,
the behavior pipeline maintains state across requests in a session.

Session-tracking wired fields
-----------------------------
  - ``session_tracking`` + ``cumulative_score_threshold`` (I-47):
    When cumulative suspicion exceeds the threshold, the rule triggers.
  - ``session_pollution_flag`` + ``rules_context_dependency`` (I-42):
    When dependent rules have triggered in this session, auto-trigger.
  - ``flags`` (I-31 ``session_leak_marker``):
    Arbitrary key-value passthrough in aggregated metadata.
"""

from __future__ import annotations

import time
from typing import Any

from kasra.analyzers.context import EvidenceItem
from kasra.core.pipeline import DetectionPipeline
from kasra.models.context import RequestContext, SessionContext
from kasra.models.enums import Stage
from kasra.models.result import AggregatedResult, DetectionResult
from kasra.models.rule import RuleDefinition


class BehaviorDetectionPipeline(DetectionPipeline):
    """Session-level behavior monitoring pipeline.

    Tracks cumulative suspicion across messages in a session and runs
    behavior-stage rules.

    This is a simple in-memory tracker.  For production use, pair it
    with a persistent session store (Redis, database).

    Usage::

        pipeline = BehaviorDetectionPipeline(registry, runner)

        # First message in session
        result1 = pipeline.run("hello", session_id="sess-1")

        # Suspicious follow-up
        result2 = pipeline.run(
            "forget your previous instructions...",
            session_id="sess-1",
        )
    """

    # Simple in-memory session store — maps session_id → SessionContext
    _sessions: dict[str, SessionContext] = {}

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._current_session: SessionContext | None = None

    def get_rules(self) -> list[RuleDefinition]:
        """Return behavior-stage + input-stage rules, ordered P0 → P1 → P2.

        Includes input-stage rules so that repeated credential / injection
        attempts across turns accumulate a suspicion score even before
        dedicated behavior rule series are loaded.
        """
        rules = list(self._registry.get_rules_for_stage(Stage.BEHAVIOR))
        input_rules = self._registry.get_rules_for_stage(Stage.INPUT)
        seen = {r.id for r in rules}
        for r in input_rules:
            if r.id not in seen:
                rules.append(r)
                seen.add(r.id)
        return rules

    # ------------------------------------------------------------------
    # Pipeline hooks overrides
    # ------------------------------------------------------------------

    def get_context(self, **kwargs: Any) -> RequestContext:
        session_id = kwargs.pop("session_id", None)
        request = RequestContext(source="behavior", **kwargs)

        if session_id:
            self._ensure_session(session_id)
            self._current_session = self._sessions[session_id]
            self._current_session.last_activity = self._now()
            self._current_session.history_count += 1
            request.suspicion_score = self._current_session.suspicion_score

        return request

    def finalize(
        self,
        aggregated: AggregatedResult,
        action_result: Any,
    ) -> AggregatedResult:
        """Update session state based on detection results.

        - Increments suspicion score for each triggered rule.
        - Adds triggered rule IDs to session history.
        - Processes session_tracking / cumulative_score_threshold rules.
        - Processes session_pollution_flag rules.
        """
        if self._current_session is not None:
            for result in aggregated.triggered_rules:
                self._current_session.suspicion_score += self._score_contribution(result)
                self._current_session.previous_results.append(result.rule_id)

            # Check cumulative_score_threshold rules (I-47)
            threshold_rules = self._get_session_tracking_rules()
            for rule in threshold_rules:
                if self._current_session.suspicion_score >= (rule.config.cumulative_score_threshold or 5):
                    # Create a virtual triggered result for the session rule
                    agg_result = DetectionResult(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        action=rule.action,
                        triggered=True,
                        matches=[],
                        evidence=[EvidenceItem(
                            rule_id=rule.id,
                            reason=f"Session suspicion score {self._current_session.suspicion_score} exceeded threshold {rule.config.cumulative_score_threshold}",
                            matching_text=f"suspicion_score={self._current_session.suspicion_score}",
                            source_layer="correlation",
                        )],
                    )
                    aggregated.add_result(agg_result)

            # Check session_pollution_flag rules (I-42)
            if self._current_session.suspicion_score > 50:
                self._current_session.is_polluted = True
                pollution_rules = self._get_pollution_rules()
                for rule in pollution_rules:
                    if rule.config.rules_context_dependency:
                        deps = rule.config.rules_context_dependency
                        dep_triggered = [
                            rid for rid in deps
                            if rid in self._current_session.previous_results
                        ]
                        if dep_triggered:
                            agg_result = DetectionResult(
                                rule_id=rule.id,
                                rule_name=rule.name,
                                severity=rule.severity,
                                action=rule.action,
                                triggered=True,
                                matches=[],
                                evidence=[EvidenceItem(
                                    rule_id=rule.id,
                                    reason=f"Session polluted — dependent rules triggered: {', '.join(dep_triggered)}",
                                    matching_text="",
                                    source_layer="correlation",
                                )],
                            )
                            aggregated.add_result(agg_result)

            # Wire up flags passthrough
            for result in aggregated.triggered_rules:
                rule_def = self._get_rule_def(result.rule_id)
                if rule_def and rule_def.config.flags:
                    for k, v in rule_def.config.flags.items():
                        aggregated.metadata[k] = v

        if action_result is not None:
            aggregated.metadata = dict(aggregated.metadata or {})
            if hasattr(action_result, 'content'):
                aggregated.metadata["processed_content"] = action_result.content

        return aggregated

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def get_session(self, session_id: str) -> SessionContext | None:
        """Get the current session context for *session_id*."""
        return self._sessions.get(session_id)

    def reset_session(self, session_id: str) -> None:
        """Reset a session's state."""
        self._sessions.pop(session_id, None)
        self._current_session = None

    def get_all_sessions(self) -> dict[str, SessionContext]:
        """Return all tracked sessions."""
        return dict(self._sessions)

    def prune_sessions(self, max_age_hours: int = 24) -> int:
        """Remove sessions older than *max_age_hours*.

        Returns:
            The number of pruned sessions.
        """
        cutoff = time.time() - (max_age_hours * 3600)
        stale = [
            sid for sid, sess in self._sessions.items()
            if sess.last_activity.timestamp() < cutoff
        ]
        for sid in stale:
            del self._sessions[sid]
        return len(stale)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_session(self, session_id: str) -> None:
        """Create a session context if one doesn't exist."""
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionContext(
                session_id=session_id,
            )

    @staticmethod
    def _score_contribution(result: DetectionResult) -> int:
        """Return the suspicion score increment for a triggered rule."""
        from kasra.models.enums import Severity
        scores = {Severity.P0: 20, Severity.P1: 10, Severity.P2: 5}
        return scores.get(result.severity, 5)

    @staticmethod
    def _now() -> Any:
        from kasra.utils.time import utcnow
        return utcnow()

    # ------------------------------------------------------------------
    # Session-tracking rule helpers
    # ------------------------------------------------------------------

    def _get_session_tracking_rules(self) -> list[RuleDefinition]:
        """Get all rules with ``session_tracking=True``."""
        all_rules = self._registry.get_rules_for_stage(Stage.INPUT)
        all_rules.extend(self._registry.get_rules_for_stage(Stage.BEHAVIOR))
        return [r for r in all_rules if r.config and r.config.session_tracking]

    def _get_pollution_rules(self) -> list[RuleDefinition]:
        """Get all rules with ``session_pollution_flag=True``."""
        all_rules = self._registry.get_rules_for_stage(Stage.INPUT)
        all_rules.extend(self._registry.get_rules_for_stage(Stage.BEHAVIOR))
        return [r for r in all_rules if r.config and r.config.session_pollution_flag]

    def _get_rule_def(self, rule_id: str) -> RuleDefinition | None:
        """Get a rule definition by ID from the registry."""
        try:
            return self._registry.get_rule(rule_id)
        except Exception:
            return None
