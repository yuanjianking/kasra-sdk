"""Kasra L3 Rule Engine — Content analysis context models.

The :class:`AnalysisContext` is the central data structure flowing through
the 5-layer analyzer pipeline.  Each layer enriches the context; later
layers consume and cross-reference earlier results.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ======================================================================
# Layer 2 — Syntactic models
# ======================================================================


class CodeBlock(BaseModel):
    """A detected code block within the content."""

    language: str | None = Field(default=None, description="Detected language of the block")
    start_line: int = Field(..., ge=0, description="0-indexed start line")
    end_line: int = Field(..., ge=0, description="0-indexed end line")
    start_char: int = Field(..., ge=0, description="Start character offset")
    end_char: int = Field(..., ge=0, description="End character offset (exclusive)")
    content_snippet: str = Field(default="", max_length=200, description="First 200 chars of the block")
    is_comment: bool = Field(default=False, description="Whether this block is a comment region")
    is_fenced: bool = Field(default=True, description="Whether the block is fenced by ``` markers")


class LanguageResult(BaseModel):
    """Result of language detection on content or a code block."""

    language: str | None = Field(default=None, description="Detected language identifier")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Detection confidence 0.0–1.0")
    evidence: list[str] = Field(default_factory=list, description="Evidence strings explaining the detection")


# ======================================================================
# Layer 3 — Semantic models
# ======================================================================


class LuhnValidation(BaseModel):
    """Result of a Luhn checksum validation on a candidate credit-card number."""

    raw_candidate: str = Field(..., description="The text that matched the CC pattern")
    normalized: str = Field(..., description="Digits-only normalized form")
    is_valid: bool = Field(..., description="Whether it passes the Luhn check")
    card_network: str | None = Field(default=None, description="Detected card network (Visa, MasterCard, etc.)")


class MatchContext(BaseModel):
    """Surrounding context extracted around a match location."""

    before: str = Field(default="", description="Text before the match (up to 200 chars)")
    after: str = Field(default="", description="Text after the match (up to 200 chars)")
    is_in_code_block: bool = Field(default=False, description="If match is inside a code block")
    code_block_language: str | None = Field(default=None, description="Language if in code block")


# ======================================================================
# Layer 4 — Correlation models
# ======================================================================


class EvidenceItem(BaseModel):
    """A single evidence node in the chain showing why a rule triggered."""

    rule_id: str = Field(..., description="The rule that triggered")
    reason: str = Field(..., description="Human-readable explanation")
    matching_text: str = Field(default="", description="The matched text")
    context_before: str = Field(default="", description="Surrounding context before match")
    context_after: str = Field(default="", description="Surrounding context after match")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence of this evidence item")
    source_layer: str = Field(default="lexical", description="Which layer produced this evidence (lexical/syntactic/semantic/correlation/external)")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When this evidence was produced")


class CorrelationHint(BaseModel):
    """A hint for cross-rule correlation from one rule to others."""

    source_rule_id: str = Field(..., description="The rule that triggered the correlation")
    target_rule_ids: list[str] = Field(..., description="Rules to correlate with")
    boost_type: str = Field(default="severity", description="severity, proximity, or chain")
    severity_override: str | None = Field(default=None, description="Override severity if correlation matches")
    proximity_window: int = Field(default=0, description="Chars before/after to search for proximity matches")


# ======================================================================
# Layer 5 — External lookup models
# ======================================================================


class ExternalLookupResult(BaseModel):
    """Result from an external service lookup."""

    source: str = Field(..., description="cve, domain_reputation, or package_registry")
    query: str = Field(..., description="What was looked up")
    found: bool = Field(default=False, description="Whether the lookup found a match")
    data: dict[str, Any] = Field(default_factory=dict, description="Additional lookup data")
    error: str | None = Field(default=None, description="Error message if lookup failed")


# ======================================================================
# Master context
# ======================================================================


class AnalysisContext(BaseModel):
    """Shared mutable context accumulated through the 5-layer pipeline.

    Layer 2 pre-populates language / code-block info before matching.
    Layer 3 enriches per-match during matching.
    Layers 4-5 run post-matching on aggregated results.
    """

    content: str = Field(default="", description="Original content being analysed (after preprocessing)")
    raw_content: str | None = Field(default=None, description="Raw content before preprocessing (for control char rules)")

    # ---- Layer 2: Syntactic ----
    detected_language: str | None = Field(default=None, description="Overall content language")
    language_confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Language detection confidence")
    language_evidence: list[str] = Field(default_factory=list, description="How language was detected")
    code_blocks: list[CodeBlock] = Field(default_factory=list, description="Code blocks found in content")

    # ---- Layer 3: Semantic ----
    luhn_validations: dict[str, list[LuhnValidation]] = Field(
        default_factory=dict,
        description="Rule ID -> list of LuhnValidation results",
    )
    match_contexts: dict[str, list[MatchContext]] = Field(
        default_factory=dict,
        description="Rule ID -> list of MatchContext per match",
    )
    structural_matches: dict[str, list[dict[str, Any]]] = Field(
        default_factory=dict,
        description="Rule ID -> list of structural analysis results",
    )

    # ---- Layer 4: Correlation ----
    correlation_hints: list[CorrelationHint] = Field(default_factory=list, description="Cross-rule correlation hints")
    severity_adjustments: dict[str, str] = Field(default_factory=dict, description="Rule ID -> adjusted severity")
    evidence_chain: list[EvidenceItem] = Field(default_factory=list, description="Full evidence chain across all rules")

    # ---- Layer 5: External ----
    external_results: list[ExternalLookupResult] = Field(default_factory=list, description="External lookup results")
