"""Kasra L3 Rule Engine — Rule definition models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, model_validator

from kasra.models.enums import ActionType, MatchMode, PatternType, Severity, Stage


class PatternDefinition(BaseModel):
    """A single detection pattern within a rule."""

    type: PatternType = Field(..., description="Pattern type (regex, keyword, entropy, composite)")
    value: str = Field(..., description="Pattern value: regex expression, keyword text, or entropy threshold")
    confidence: float = Field(default=0.7, ge=0.0, le=8.0, description="Confidence score (0.0–1.0 for regex/keyword) or entropy threshold (0.0–8.0 for entropy type)")

    # Entropy-specific fields (used when type=entropy)
    min_entropy: float | None = Field(default=None, ge=0.0, le=8.0, description="Minimum Shannon entropy threshold")
    min_length: int | None = Field(default=None, ge=1, description="Minimum string length for entropy check")

    # Composite-specific fields (used when type=composite)
    sub_patterns: list[PatternDefinition] | None = Field(default=None, description="Sub-patterns for composite matching")


class DetectionConfig(BaseModel):
    """Configuration for a rule's detection behaviour."""

    mode: MatchMode = Field(default=MatchMode.ANY, description="How patterns are combined (any=OR, all=AND)")
    patterns: list[PatternDefinition] = Field(default_factory=list, description="Detection patterns")
    max_matches: int = Field(default=10, ge=1, le=1000, description="Maximum number of matches to report")
    min_length: int | None = Field(default=None, ge=1, description="Minimum content length to trigger detection")
    exclusions: list[str] = Field(default_factory=list, description="Regex patterns for false-positive exclusion")
    scopes: list[Stage] | None = Field(default=None, description="Stages this rule applies to (None = all)")
    languages: list[str] | None = Field(default=None, description="If set, rule only applies when content language matches one of these")


class SeverityOverride(BaseModel):
    """Severity reduction mapping for modifier rules."""

    rule_id: str = Field(..., description="Rule ID to override")
    override_severity: Severity = Field(..., description="Reduced severity level")


class RuleConfig(BaseModel):
    """Extended rule configuration."""

    max_matches: int = Field(default=10, ge=1, le=10000)
    exclusions: list[str] = Field(default_factory=list)
    redact_template: str | None = Field(default=None)
    luhn_check: bool = Field(default=False)
    normalize: bool | str | None = Field(default=None)
    scopes: list[str] | None = Field(default=None)
    link_to_rules: list[str] | None = Field(default=None)
    modifier_rule: bool = Field(default=False)
    severity_reduction: dict[str, str] | None = Field(default=None)
    dynamic: bool = Field(default=False)
    session_tracking: bool = Field(default=False)
    cumulative_score_threshold: int | None = Field(default=None)
    no_pattern_match: bool = Field(default=False)
    admin_alert: bool = Field(default=False)
    compliance_audit: bool = Field(default=False)
    gdpr_audit: bool = Field(default=False)
    session_pollution_flag: bool = Field(default=False)
    max_length: int | None = Field(default=None)
    context_boost: dict[str, Any] | None = Field(default=None)
    flags: dict[str, Any] | None = Field(default=None)
    rules_context_dependency: list[str] | None = Field(default=None)


class RuleDefinition(BaseModel):
    """Complete definition of a single security rule."""

    id: str = Field(..., pattern=r"^[A-Z]+-\d{2,3}$", description="Rule ID, e.g. I-01, O-15, SEC-03")
    name: str = Field(..., min_length=1, max_length=200, description="Human-readable rule name")
    description: str = Field(..., min_length=1, max_length=2000, description="Detailed rule description")
    category: str = Field(..., description="Rule category for grouping (credential_leak, pii, injection, etc.)")
    severity: Severity = Field(..., description="Rule severity: P0 (Critical), P1 (High), P2 (Medium)")
    action: ActionType = Field(..., description="Action to take on match")
    applicable_stages: list[str] = Field(default_factory=lambda: ["input"], description="Pipeline stages this rule applies to")

    detection: DetectionConfig = Field(default_factory=DetectionConfig, description="Detection configuration")
    config: RuleConfig = Field(default_factory=RuleConfig, description="Extended rule configuration")

    enabled: bool = Field(default=True, description="Whether the rule is enabled at load time")

    @model_validator(mode="after")
    def validate_severity_action_consistency(self) -> "RuleDefinition":
        """Validate that P0 severity requires block or redact action."""
        if self.severity == Severity.P0 and self.action not in (ActionType.BLOCK, ActionType.REDACT, ActionType.WARN):
            raise ValueError(f"P0 rule {self.id} must use block, redact or warn action, got {self.action}")
        if self.severity == Severity.P2 and self.action == ActionType.BLOCK:
            raise ValueError(f"P2 rule {self.id} should not use block action (use warn or redact instead)")
        return self


class RuleBundle(BaseModel):
    """A bundle of rules for one series (e.g. all I-series rules)."""

    bundle: dict[str, Any] = Field(..., description="Bundle metadata (series, name, version, total)")
    rules: list[RuleDefinition] = Field(..., min_length=1, description="Rules in this bundle")
