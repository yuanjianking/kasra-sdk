"""Kasra L3 Rule Engine — Multi-layer content analyzers.

This package implements a 5-layer detection architecture that extends
the rule engine beyond pure lexical matching (regex / keyword / entropy):

Layer 1 — Lexical (existing matchers)
    Regex, keyword, entropy, and composite pattern matching.
    Unchanged — see :mod:`kasra.matchers`.

Layer 2 — Syntactic (NEW)
    Language detection, code-block boundary identification,
    structural pattern matching (function calls, arguments).

Layer 3 — Semantic (NEW)
    Luhn checksum validation, surrounding-context analysis,
    language-specific pattern refinement.

Layer 4 — Correlation (NEW)
    Cross-rule evidence aggregation (context_boost, link_to_rules),
    severity adjustment, evidence chain construction.

Layer 5 — External (NEW, scaffold)
    Interface definitions for CVE / domain / package-registry lookups.
    Real implementations are injected via plugin hooks.

Usage::

    from kasra.analyzers import AnalyzerPipeline

    pipeline = AnalyzerPipeline.create_default()
    context = pipeline.execute(content)
    # context.detected_language  →  "python"
    # context.code_blocks        →  list of CodeBlock
    # context.evidence_chain     →  list of EvidenceItem
"""

from __future__ import annotations

from kasra.analyzers.base import Analyzer, AnalyzerPipeline
from kasra.analyzers.context import (
    AnalysisContext,
    CodeBlock,
    CorrelationHint,
    EvidenceItem,
    ExternalLookupResult,
    LuhnValidation,
    MatchContext,
)

__all__ = [
    "Analyzer",
    "AnalyzerPipeline",
    "AnalysisContext",
    "CodeBlock",
    "CorrelationHint",
    "EvidenceItem",
    "ExternalLookupResult",
    "LuhnValidation",
    "MatchContext",
]
