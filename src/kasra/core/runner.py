"""Kasra L3 Rule Engine — Rule runner.

The :class:`RuleRunner` takes a content string and a ``RuleDefinition``,
dispatches each pattern to the appropriate matcher, combines results
based on the rule's detection mode (ANY / ALL), and returns a
``DetectionResult``.

The :class:`MatcherDispatcher` selects the correct ``PatternMatcher``
implementation for each ``PatternType``.

Analyser integration
--------------------
The runner now integrates with the 5-layer analyser architecture:

  **Layer 2 (Syntactic)** — runs as a pre-processing step in
  :meth:`run_rules` before any rules execute.  Language detection
  and code-block analysis results are cached in ``AnalysisContext``
  and reused across all rules.

  **Layer 3 (Semantic)** — runs per-rule as post-match processing.
  Luhn validation (for credit cards), surrounding-context extraction,
  and language-specific confidence adjustments happen here.

  **Layer 4 (Correlation)** — runs after all rules in
  :class:`DetectionPipeline._aggregate`.  See :mod:`kasra.analyzers.correlator`.
"""

from __future__ import annotations

import time
from typing import Any

from kasra.matchers.composite_matcher import CompositeMatcher
from kasra.matchers.entropy_matcher import EntropyMatcher
from kasra.matchers.keyword_matcher import KeywordMatcher
from kasra.matchers.regex_matcher import ReMatcher
from kasra.models.enums import MatchMode, PatternType
from kasra.models.result import DetectionResult, MatchResult, MatchSpan
from kasra.models.rule import PatternDefinition, RuleDefinition
from kasra.matchers.base import PatternMatcher
from kasra.analyzers.context import AnalysisContext, EvidenceItem, MatchContext
from kasra.rules.checks import has_checker, get_checker
from kasra.analyzers.semgrep_adapter import SemgrepRunner, has_semgrep_patterns


# ---------------------------------------------------------------------------
# Matcher dispatcher — routes PatternType -> PatternMatcher
# ---------------------------------------------------------------------------

class MatcherDispatcher:
    """Holds one instance of each matcher type and dispatches by pattern type.

    All matchers are created once at startup and reused across all rules.
    """

    def __init__(self) -> None:
        self._matchers: dict[PatternType, PatternMatcher] = {
            PatternType.REGEX: ReMatcher(),
            PatternType.KEYWORD: KeywordMatcher(),
            PatternType.ENTROPY: EntropyMatcher(),
            PatternType.COMPOSITE: CompositeMatcher(),
        }

    def match(
        self,
        content: str,
        pattern: PatternDefinition,
        max_matches: int = 10,
    ) -> list[MatchResult]:
        """Dispatch *pattern* to the correct matcher and return results.

        Args:
            content: The text content to scan.
            pattern: The pattern definition.
            max_matches: Maximum number of matches to return.

        Returns:
            A list of ``MatchResult`` objects (empty if no match).
        """
        matcher = self._matchers.get(pattern.type)
        if matcher is None:
            return []
        try:
            return matcher.match_all(content, pattern, max_matches=max_matches)
        except Exception:
            return []


# ---------------------------------------------------------------------------
# Rule runner
# ---------------------------------------------------------------------------

_semgrep_runner: SemgrepRunner | None = None


def _match_via_semgrep(
    content: str,
    rule_id: str,
    all_matches: list[MatchResult],
    evidence: list[EvidenceItem],
) -> None:
    """Run *rule_id* against *content* via Semgrep (if available).

    Matches are prepended to *all_matches* with evidence chain entries.
    """
    global _semgrep_runner

    if not has_semgrep_patterns(rule_id):
        return

    if _semgrep_runner is None:
        _semgrep_runner = SemgrepRunner()
    runner = _semgrep_runner

    if not runner.available:
        return

    try:
        findings = runner.run("<inline>", content, rule_id)
        for f in findings:
            span = MatchSpan(start=f.line_number, end=f.line_number, matched=f.matched_text[:200])
            all_matches.append(MatchResult(
                rule_id=rule_id,
                pattern_index=0,
                pattern_type="regex",
                pattern_value=f"semgrep/{rule_id}",
                confidence=f.confidence,
                spans=[span],
                matched_text=f.matched_text[:200],
            ))
            evidence.append(EvidenceItem(
                rule_id=rule_id,
                reason=f"Semgrep match: {f.matched_text[:80]}",
                matching_text=f.matched_text[:200],
                confidence=f.confidence,
                source_layer="lexical",
            ))
    except Exception:
        pass


class RuleRunner:
    """Executes a single rule definition against content.

    Usage::

        runner = RuleRunner()
        result = runner.run_rule(content, rule_definition)
    """

    def __init__(
        self,
        dispatcher: MatcherDispatcher | None = None,
    ) -> None:
        self._dispatcher = dispatcher or MatcherDispatcher()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_max_matches(rule: RuleDefinition) -> int:
        """Resolve the effective max_matches from config or detection."""
        # Prefer config.max_matches (where rules actually store it),
        # fall back to detection.max_matches (the model default).
        if rule.config and rule.config.max_matches is not None:
            return rule.config.max_matches
        return rule.detection.max_matches

    @staticmethod
    def _resolve_exclusions(rule: RuleDefinition) -> list[str]:
        """Resolve effective exclusions from config or detection."""
        if rule.config and rule.config.exclusions:
            return rule.config.exclusions
        return rule.detection.exclusions

    def run_rule(
        self,
        content: str,
        rule: RuleDefinition,
        analysis_context: AnalysisContext | None = None,
    ) -> DetectionResult:
        """Run *rule* against *content* and return a ``DetectionResult``.

        Handles:
          - Config-only rules (no_pattern_match flag with max_length etc.).
          - Individual pattern execution via ``MatcherDispatcher``.
          - Combination logic (ANY / ALL mode).
          - **Luhn validation** (post-match, when ``rule.config.luhn_check``).
          - **Language filter** (when ``rule.detection.languages`` is set).
          - **Evidence chain** (attached to ``DetectionResult.evidence``).
          - Timing and error capture per rule.

        Args:
            content: The text content to scan.
            rule: The rule definition to evaluate.
            analysis_context: Optional analysis context from Layer 2+ pipeline.

        Returns:
            A ``DetectionResult`` with ``triggered=True`` if the rule fired.
        """
        start = time.perf_counter()
        error: str | None = None
        triggered = False
        all_matches: list[MatchResult] = []
        evidence: list[EvidenceItem] = []
        effective_max_matches: int = rule.detection.max_matches

        try:
            # Config-only rules: no patterns, check config fields instead
            if rule.config and rule.config.no_pattern_match:
                return self._run_config_checks(content, rule, analysis_context, start)

            # No patterns defined → not triggered
            if not rule.detection.patterns:
                return self._empty_result(rule, start)

            # Language filter: skip if rule targets a specific language
            # and content is detected as a different language.
            # Python checkers handle their own language logic, skip this filter.
            if not has_checker(rule.id):
                if analysis_context and self._should_skip_for_language(rule, analysis_context):
                    return self._empty_result(rule, start)

            # Min-length check: skip if content is too short
            min_len = rule.detection.min_length
            if min_len is not None and len(content) < min_len:
                return self._empty_result(rule, start)

            # Normalize override: if rule specifies a normalization form
            # (e.g. NFKC for I-32 homoglyph detection), re-normalize content
            if rule.config and rule.config.normalize:
                import unicodedata
                norm_form = rule.config.normalize
                if isinstance(norm_form, str) and norm_form.upper() in ("NFC", "NFKC", "NFD", "NFKD"):
                    content = unicodedata.normalize(norm_form.upper(), content)

            # Exclusions: skip if content matches any false-positive filter
            exclusions = self._resolve_exclusions(rule)
            if exclusions:
                import re
                for excl_pattern in exclusions:
                    try:
                        if re.search(excl_pattern, content):
                            return self._empty_result(rule, start)
                    except re.error:
                        pass

            # Language evidence
            if analysis_context and analysis_context.detected_language:
                evidence.append(EvidenceItem(
                    rule_id=rule.id,
                    reason=f"Content language detected as: {analysis_context.detected_language} (confidence {analysis_context.language_confidence})",
                    matching_text="",
                    confidence=analysis_context.language_confidence,
                    source_layer="syntactic",
                ))

            # Python checker: if this rule has a dedicated checker, run it
            effective_max_matches = self._resolve_max_matches(rule)
            if has_checker(rule.id):
                try:
                    checker = get_checker(rule.id)
                    raw_matches = checker(content)
                    if raw_matches:
                        triggered = True
                        for rm in raw_matches[:effective_max_matches]:
                            span = MatchSpan(start=rm["start"], end=rm["end"], matched=rm["matched"][:200])
                            all_matches.append(MatchResult(
                                rule_id=rule.id,
                                pattern_index=0,
                                pattern_type="regex",
                                pattern_value=rm.get("pattern", ""),
                                confidence=rm["confidence"],
                                spans=[span],
                                matched_text=rm["matched"][:200],
                            ))
                            evidence.append(EvidenceItem(
                                rule_id=rule.id,
                                reason=rm.get("pattern", "Python checker match"),
                                matching_text=rm["matched"][:200],
                                confidence=rm["confidence"],
                                source_layer="lexical",
                            ))
                except Exception:
                    pass

            # ── Semgrep AST matching (optional, preferred over regex) ──
            _match_via_semgrep(content, rule.id, all_matches, evidence)

            # Also run standard regex patterns (complements Python checkers / semgrep)
            pattern_results: list[list[MatchResult]] = []
            for idx, pattern in enumerate(rule.detection.patterns):
                matches = self._dispatcher.match(
                    content,
                    pattern,
                    max_matches=effective_max_matches,
                )
                for m in matches:
                    m.rule_id = rule.id
                    m.pattern_index = idx
                pattern_results.append(matches)

            # Combine based on mode
            if rule.detection.mode == MatchMode.ALL:
                if all(len(pr) > 0 for pr in pattern_results):
                    triggered = True
                    for pr in pattern_results:
                        all_matches.extend(pr)
            else:
                for pr in pattern_results:
                    if pr:
                        triggered = True
                        all_matches.extend(pr)
                        if rule.detection.mode == MatchMode.ANY:
                            break

            # ---- Layer 3: Post-match semantic processing ----

            if triggered:
                # Apply redact_template from rule config to match spans
                if rule.config and rule.config.redact_template:
                    for match in all_matches:
                        for span in match.spans:
                            span.redacted = rule.config.redact_template

                # Luhn validation for credit-card rules
                if rule.config and rule.config.luhn_check and all_matches:
                    self._apply_luhn_validation(content, rule, all_matches, evidence, analysis_context)
                    # If all matches were filtered out, rule no longer triggered
                    if not all_matches:
                        triggered = False

                # Surrounding context for each match
                if analysis_context:
                    self._attach_match_contexts(content, all_matches, evidence, analysis_context)

        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"

        elapsed = (time.perf_counter() - start) * 1000

        return DetectionResult(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            action=rule.action,
            triggered=triggered,
            matches=all_matches[: effective_max_matches],
            error=error,
            evidence=evidence,
        )

    def run_rules(
        self,
        content: str,
        rules: list[RuleDefinition],
        analysis_context: AnalysisContext | None = None,
    ) -> list[DetectionResult]:
        """Run multiple rules against *content*.

        When *analysis_context* is provided, Layer 2 syntactic analysis
        results (language detection, code blocks) are available to all rules.

        Args:
            content: The text content to scan.
            rules: A list of rule definitions to evaluate.
            analysis_context: Optional pre-computed analysis context.

        Returns:
            A list of ``DetectionResult`` objects, one per rule.
        """
        return [
            self.run_rule(content, rule, analysis_context=analysis_context)
            for rule in rules
        ]

    # ------------------------------------------------------------------
    # Config-only rule processing
    # ------------------------------------------------------------------

    def _run_config_checks(
        self,
        content: str,
        rule: RuleDefinition,
        analysis_context: AnalysisContext | None,
        start: float,
    ) -> DetectionResult:
        """Process rules with ``no_pattern_match=True``.

        These rules have no patterns and rely on config fields:
        - ``max_length`` — triggers if content exceeds the threshold.
        - Additional config checks can be added here.

        This fixes the bug where ``no_pattern_match`` rules always returned
        non-triggered results.
        """
        triggered = False
        matches: list[MatchResult] = []
        evidence: list[EvidenceItem] = []

        # max_length check
        if rule.config and rule.config.max_length is not None:
            content_len = len(content)
            if content_len > rule.config.max_length:
                triggered = True
                matches.append(MatchResult(
                    rule_id=rule.id,
                    pattern_index=0,
                    pattern_type="config",
                    pattern_value=f"max_length={rule.config.max_length}",
                    confidence=1.0,
                    matched_text=f"Content length {content_len} exceeds max {rule.config.max_length}",
                ))
                evidence.append(EvidenceItem(
                    rule_id=rule.id,
                    reason=f"Content length {content_len} exceeds max_length={rule.config.max_length}",
                    matching_text=f"length={content_len}",
                    confidence=1.0,
                    source_layer="semantic",
                ))

        elapsed = (time.perf_counter() - start) * 1000
        return DetectionResult(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            action=rule.action,
            triggered=triggered,
            matches=matches,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # Language filter
    # ------------------------------------------------------------------

    @staticmethod
    def _should_skip_for_language(rule: RuleDefinition, context: AnalysisContext) -> bool:
        """Check if a rule targets a language that doesn't match the content."""
        rule_languages = rule.detection.languages
        if not rule_languages:
            return False  # Rule applies to all languages
        if not context.detected_language:
            return False  # Can't determine language, don't skip
        if context.language_confidence < 0.3:
            return False  # Language detection too uncertain
        return context.detected_language not in rule_languages

    # ------------------------------------------------------------------
    # Luhn validation post-processing
    # ------------------------------------------------------------------

    @staticmethod
    def _apply_luhn_validation(
        content: str,
        rule: RuleDefinition,
        matches: list[MatchResult],
        evidence: list[EvidenceItem],
        analysis_context: AnalysisContext | None,
    ) -> None:
        """Remove matches whose candidates fail the Luhn checksum.

        Mutates *matches* in place (removes invalid matches).
        """
        from kasra.analyzers.luhn_validator import LuhnValidator

        validator = LuhnValidator()
        valid_matches: list[MatchResult] = []

        for match in matches:
            # Re-validate each span
            valid_spans = []
            for span in match.spans:
                candidate = span.matched
                validation = validator.validate(candidate)
                if validation.is_valid:
                    valid_spans.append(span)
                else:
                    evidence.append(EvidenceItem(
                        rule_id=rule.id,
                        reason=f"Credit card candidate '{candidate[:20]}...' failed Luhn checksum — filtered out",
                        matching_text=candidate[:100],
                        confidence=0.5,
                        source_layer="semantic",
                    ))
                # Store validation in analysis context
                if analysis_context is not None:
                    if rule.id not in analysis_context.luhn_validations:
                        analysis_context.luhn_validations[rule.id] = []
                    analysis_context.luhn_validations[rule.id].append(validation)

            if valid_spans:
                match.spans = valid_spans
                valid_matches.append(match)

        matches[:] = valid_matches

    # ------------------------------------------------------------------
    # Context attachment
    # ------------------------------------------------------------------

    @staticmethod
    def _attach_match_contexts(
        content: str,
        matches: list[MatchResult],
        evidence: list[EvidenceItem],
        analysis_context: AnalysisContext,
    ) -> None:
        """Attach surrounding context to each match for evidence chain."""
        from kasra.analyzers.context_analyzer import SurroundingContextAnalyzer

        ctx_analyzer = SurroundingContextAnalyzer()

        for match in matches:
            for span in match.spans:
                match_ctx = ctx_analyzer.extract(
                    content, span.start, span.end,
                    code_blocks=analysis_context.code_blocks,
                )

                # Store in analysis context
                if match.rule_id not in analysis_context.match_contexts:
                    analysis_context.match_contexts[match.rule_id] = []
                analysis_context.match_contexts[match.rule_id].append(match_ctx)

                evidence.append(EvidenceItem(
                    rule_id=match.rule_id,
                    reason=f"Pattern matched at position {span.start}-{span.end}",
                    matching_text=span.matched[:200],
                    context_before=match_ctx.before[:200],
                    context_after=match_ctx.after[:200],
                    confidence=1.0,
                    source_layer="lexical",
                ))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _empty_result(rule: RuleDefinition, start: float) -> DetectionResult:
        elapsed = (time.perf_counter() - start) * 1000
        return DetectionResult(
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            action=rule.action,
            triggered=False,
            matches=[],
        )
