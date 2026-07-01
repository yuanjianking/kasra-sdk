"""Kasra L3 Rule Engine — Result models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from kasra.analyzers.context import EvidenceItem
from kasra.models.enums import ActionType, Severity
from kasra.utils.severity import SEVERITY_RANK
from kasra.utils.time import utcnow


class MatchSpan(BaseModel):
    """A specific matched span within the content."""

    start: int = Field(..., ge=0, description="Start position in content (0-indexed)")
    end: int = Field(..., ge=0, description="End position in content (exclusive)")
    matched: str = Field(..., description="The matched text snippet")
    redacted: str | None = Field(default=None, description="Redacted replacement text, if action is redact")


class MatchResult(BaseModel):
    """Result of matching a single pattern within a rule."""

    rule_id: str = Field(..., description="Rule ID that matched")
    pattern_index: int = Field(default=0, ge=0, description="Index of the matched pattern within the rule")
    pattern_type: str = Field(default="regex", description="Type of the matched pattern")
    pattern_value: str = Field(default="", description="The pattern value that matched")
    confidence: float = Field(default=0.7, ge=0.0, le=1.0, description="Confidence of this match")
    spans: list[MatchSpan] = Field(default_factory=list, description="Matched spans in the content")
    matched_text: str | None = Field(default=None, description="Short matched text snippet")
    matched_at: datetime = Field(default_factory=utcnow, description="Timestamp of the match")


class DetectionResult(BaseModel):
    """Result of running a single rule against content."""

    rule_id: str = Field(..., description="Rule ID")
    rule_name: str = Field(..., description="Rule name")
    severity: Severity = Field(..., description="Effective severity")
    action: ActionType = Field(..., description="Effective action")
    triggered: bool = Field(default=False, description="Whether the rule triggered")
    matches: list[MatchResult] = Field(default_factory=list, description="Individual match results")
    error: str | None = Field(default=None, description="Error message if rule execution failed")

    # Layer 2-4: Evidence chain (populated by analyzers and correlator)
    evidence: list[EvidenceItem] = Field(
        default_factory=list,
        description="Structured evidence chain explaining why this rule triggered",
    )

    @property
    def match_count(self) -> int:
        """Total number of match spans across all matches."""
        return sum(len(m.spans) for m in self.matches)


class AggregatedResult(BaseModel):
    """Aggregated result from running multiple rules against content."""

    overall_action: ActionType = Field(default=ActionType.WARN, description="Highest-priority action across all rules")
    overall_severity: Severity = Field(default=Severity.P2, description="Highest severity across triggered rules")
    triggered_rules: list[DetectionResult] = Field(default_factory=list, description="All triggered rule results")
    all_results: list[DetectionResult] = Field(default_factory=list, description="All rule results (triggered + non-triggered)")
    blocked: bool = Field(default=False, description="Whether content was blocked")
    warnings: list[str] = Field(default_factory=list, description="Warning messages for the user")
    redact_spans: list[MatchSpan] = Field(default_factory=list, description="Spans to redact (for output pipeline)")
    truncated: bool = Field(default=False, description="Whether content was truncated")
    admin_alert: bool = Field(default=False, description="Whether an admin alert should be raised (from admin_alert rules)")
    compliance_audit: bool = Field(default=False, description="Whether a compliance audit event should be logged")
    gdpr_audit: bool = Field(default=False, description="Whether a GDPR audit event should be logged")
    execution_time_ms: float = Field(default=0.0, description="Total execution time in milliseconds")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Pipeline-specific metadata (processed content, file path, etc.)")

    # Layer 2-4: Full analysis context (populated by analyzer pipeline)
    analysis_context: Any | None = Field(
        default=None,
        description="Full 5-layer analysis context for audit/reporting",
    )

    def add_result(self, result: DetectionResult) -> None:
        """Add a detection result and update aggregated state."""
        self.all_results.append(result)
        if not result.triggered:
            return
        self.triggered_rules.append(result)

        # Conflict resolution: determine overall action
        for m in result.matches:
            for span in m.spans:
                self.redact_spans.append(span)

        if result.severity == Severity.P0 and result.action in (ActionType.BLOCK, ActionType.REDACT):
            self.blocked = True
            self.overall_action = ActionType.BLOCK
            self.overall_severity = Severity.P0

        if result.action == ActionType.WARN:
            for m in result.matches:
                if m.matched_text:
                    self.warnings.append(f"[{result.rule_id}] {result.rule_name}: {m.matched_text[:100]}")

        # Upgrade severity if higher than current (lower rank = more severe)
        current_rank = SEVERITY_RANK.get(self.overall_severity, 99)
        new_rank = SEVERITY_RANK.get(result.severity, 99)
        if new_rank < current_rank:
            self.overall_severity = result.severity
