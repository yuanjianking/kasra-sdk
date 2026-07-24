"""Kasra L3 Rule Engine — Composite matcher.

Combines multiple sub-patterns with logical operators for complex
detection scenarios that a single regex cannot express.

Operators
---------
  AND  — All sub-patterns must match in the content.
  OR   — At least one sub-pattern matches.
  NOT  — A sub-pattern must NOT appear in the content
         (prefix sub-pattern value with ``!`` or set ``confidence=0.0``).
  NEAR — Sub-patterns must match within N characters of each other
         (encode proximity in ``pattern.value``, e.g. ``near:200``).

Usage in rules JSON::

    {
      "type": "composite",
      "value": "near:300",
      "sub_patterns": [
        {"type": "keyword", "value": "password", "confidence": 0.7},
        {"type": "keyword", "value": "=", "confidence": 0.3},
        {"type": "regex", "value": "[\"'].{8,}[\"']", "confidence": 0.5}
      ]
    }

This matches ``password = \"supersecret\"`` within 300 chars.
"""

from __future__ import annotations

import re
from typing import Any

from kasra.exceptions.errors import PatternCompileError
from kasra.matchers.base import PatternMatcher
from kasra.matchers.regex_matcher import ReMatcher
from kasra.matchers.keyword_matcher import KeywordMatcher
from kasra.matchers.entropy_matcher import EntropyMatcher
from kasra.models.result import MatchResult, MatchSpan
from kasra.models.rule import PatternDefinition


class CompositeMatcher(PatternMatcher):
    """Orchestrates sub-patterns with AND / OR / NOT / NEAR semantics.

    The dispatcher routes each sub-pattern to the correct matcher
    (regex, keyword, entropy) based on its ``type``.
    """

    def __init__(
        self,
        regex_matcher: ReMatcher | None = None,
        keyword_matcher: KeywordMatcher | None = None,
        entropy_matcher: EntropyMatcher | None = None,
        case_insensitive: bool = True,
    ) -> None:
        self._regex = regex_matcher or ReMatcher(case_insensitive=case_insensitive)
        self._keyword = keyword_matcher or KeywordMatcher()
        self._entropy = entropy_matcher or EntropyMatcher()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def match(self, content: str, pattern: PatternDefinition) -> MatchResult | None:
        if not pattern.sub_patterns:
            return None

        # Parse operator and proximity from pattern.value
        operator, proximity = self._parse_mode(pattern.value)

        # Evaluate each sub-pattern
        sub_results: list[tuple[PatternDefinition, list[MatchResult]]] = []
        for sub in pattern.sub_patterns:
            matches = self._match_sub(sub, content)
            sub_results.append((sub, matches))

        # Apply operator logic
        return self._combine(
            operator=operator,
            sub_results=sub_results,
            proximity=proximity,
            pattern=pattern,
        )

    def match_all(
        self,
        content: str,
        pattern: PatternDefinition,
        max_matches: int = 10,
    ) -> list[MatchResult]:
        result = self.match(content, pattern)
        return [result] if result is not None else []

    def validate(self, pattern: PatternDefinition) -> None:
        if not pattern.sub_patterns:
            raise ValueError("Composite pattern must specify sub_patterns")
        for sub in pattern.sub_patterns:
            # Delegate validation to sub-matchers
            if sub.type.value == "regex":
                self._regex.validate(sub)
            elif sub.type.value == "keyword":
                if not sub.value:
                    raise ValueError("Keyword sub-pattern must have non-empty value")
            elif sub.type.value == "entropy":
                self._entropy.validate(sub)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_mode(value: str) -> tuple[str, int]:
        """Parse ``pattern.value`` into (operator, proximity_chars).

        Allowed values:
          - ``"and"``
          - ``"or"``
          - ``"not"``
          - ``"near:N"`` where N is max char distance
          - empty / unknown → ``"and"``
        """
        v = value.strip().lower()
        if v.startswith("near:"):
            try:
                prox = int(v[5:].strip())
                return "near", max(1, prox)
            except (ValueError, IndexError):
                return "near", 500
        if v == "or":
            return "or", 0
        if v == "not":
            return "not", 0
        if v == "and":
            return "and", 0
        return "and", 0  # default

    def _match_sub(
        self,
        sub: PatternDefinition,
        content: str,
    ) -> list[MatchResult]:
        """Run a single sub-pattern through the correct matcher.

        Handles recursive composite sub-patterns by creating a transient
        CompositeMatcher for the nested level.
        """
        sub_type = sub.type.value

        if sub_type == "regex":
            return self._regex.match_all(content, sub)
        if sub_type == "keyword":
            return self._keyword.match_all(content, sub)
        if sub_type == "entropy":
            return self._entropy.match_all(content, sub)
        if sub_type == "composite":
            # Recursive composite matching — creates a fresh composite
            # for this level to avoid cross-level state pollution
            nested = CompositeMatcher(self._regex, self._keyword, self._entropy)
            result = nested.match(content, sub)
            return [result] if result is not None else []
        return []

    # ------------------------------------------------------------------
    # Combine
    # ------------------------------------------------------------------

    def _combine(
        self,
        operator: str,
        sub_results: list[tuple[PatternDefinition, list[MatchResult]]],
        proximity: int,
        pattern: PatternDefinition,
    ) -> MatchResult | None:
        if operator == "or":
            return self._combine_or(sub_results, pattern)
        if operator == "not":
            return self._combine_not(sub_results, pattern)
        if operator == "near":
            return self._combine_near(sub_results, proximity, pattern)
        return self._combine_and(sub_results, pattern)  # default: AND

    @staticmethod
    def _has_negative(sub: PatternDefinition) -> bool:
        """Check if a sub-pattern is a NOT constraint."""
        return sub.confidence == 0.0 or sub.value.startswith("!")

    def _combine_and(
        self,
        sub_results: list[tuple[PatternDefinition, list[MatchResult]]],
        pattern: PatternDefinition,
    ) -> MatchResult | None:
        """AND: all non-NOT sub-patterns must match; NOT sub-patterns must NOT match."""
        all_matches: list[MatchResult] = []

        for sub, matches in sub_results:
            if self._has_negative(sub):
                # NOT constraint: sub-pattern must NOT match
                actual_value = sub.value.lstrip("!")
                if matches:
                    return None
            else:
                # Positive constraint: must match
                if not matches:
                    return None
                all_matches.extend(matches)

        if not all_matches:
            return None

        return self._build_result(all_matches, pattern, "AND")

    def _combine_or(
        self,
        sub_results: list[tuple[PatternDefinition, list[MatchResult]]],
        pattern: PatternDefinition,
    ) -> MatchResult | None:
        """OR: at least one sub-pattern matches (excluding NOT)."""
        all_matches: list[MatchResult] = []

        for sub, matches in sub_results:
            if self._has_negative(sub):
                if matches:
                    return None  # NOT constraint violated → no match
            else:
                if matches:
                    all_matches.extend(matches)
                    return self._build_result(all_matches, pattern, "OR")

        return None

    def _combine_not(
        self,
        sub_results: list[tuple[PatternDefinition, list[MatchResult]]],
        pattern: PatternDefinition,
    ) -> MatchResult | None:
        """NOT: first sub-pattern must NOT match, second must match."""
        if len(sub_results) < 2:
            return None

        first, first_matches = sub_results[0]
        # If first sub-pattern matches, NOT fails
        if first_matches:
            return None

        # Second (and subsequent) must match
        for sub, matches in sub_results[1:]:
            if matches:
                return self._build_result(matches, pattern, "NOT")

        return None

    def _combine_near(
        self,
        sub_results: list[tuple[PatternDefinition, list[MatchResult]]],
        proximity: int,
        pattern: PatternDefinition,
    ) -> MatchResult | None:
        """NEAR: all sub-patterns must match within *proximity* chars of each other."""
        # First, all must match (AND baseline)
        positive_matches: list[MatchResult] = []
        for sub, matches in sub_results:
            if self._has_negative(sub):
                if matches:
                    return None
            else:
                if not matches:
                    return None
                positive_matches.extend(matches)

        if len(positive_matches) < 2:
            return None  # Need at least 2 for proximity

        # Collect all match spans
        all_spans: list[tuple[int, int]] = []
        for m in positive_matches:
            for s in m.spans:
                all_spans.append((s.start, s.end))

        if len(all_spans) < 2:
            return None

        # Check if any span is within proximity of any other span
        for i in range(len(all_spans)):
            for j in range(i + 1, len(all_spans)):
                s1_start, s1_end = all_spans[i]
                s2_start, s2_end = all_spans[j]
                distance = min(abs(s1_end - s2_start), abs(s2_end - s1_start))
                if distance <= proximity:
                    spans = [
                        MatchSpan(start=s1_start, end=s1_end, matched=""),
                        MatchSpan(start=s2_start, end=s2_end, matched=""),
                    ]
                    return MatchResult(
                        rule_id="",
                        pattern_index=0,
                        pattern_type="composite",
                        pattern_value=f"near:{proximity}",
                        confidence=0.8,
                        spans=spans,
                        matched_text=pattern.sub_patterns[0].value,
                    )

        return None  # No spans close enough

    # ------------------------------------------------------------------
    # Result builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_result(
        matches: list[MatchResult],
        pattern: PatternDefinition,
        operator: str,
    ) -> MatchResult:
        """Merge multiple MatchResults into one composite result."""
        all_spans: list[MatchSpan] = []
        max_confidence = 0.0

        for m in matches:
            all_spans.extend(m.spans)
            max_confidence = max(max_confidence, m.confidence)

        # Build representative matched_text from all sub-patterns
        sub_values = [s.value for s in (pattern.sub_patterns or [])]
        matched_text = " | ".join(sub_values[:5])

        return MatchResult(
            rule_id="",
            pattern_index=0,
            pattern_type="composite",
            pattern_value=f"composite:{operator}",
            confidence=max_confidence or 0.7,
            spans=all_spans[:10],
            matched_text=matched_text[:200],
        )
