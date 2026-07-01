"""Kasra L3 Rule Engine — Keyword matcher using Aho-Corasick automaton.

Uses ``ahocorasick_rs`` (Rust-backed) for O(n) multi-keyword matching.
"""

from __future__ import annotations

from typing import Any

import ahocorasick_rs

from kasra.matchers.base import PatternMatcher
from kasra.models.result import MatchResult, MatchSpan
from kasra.models.rule import PatternDefinition


class KeywordMatcher(PatternMatcher):
    """Aho-Corasick keyword matcher.

    Builds an automaton lazily for each set of keywords.  In practice the
    caller should batch patterns together because the automaton is built
    per-pattern (each ``RuleDefinition`` typically has 1-5 keyword patterns).

    ``ahocorasick_rs.find_matches_as_indexes`` returns tuples of the form
    ``(match_id, start, end)`` where *start* is the byte offset where the
    match begins and *end* is the byte offset where it ends (exclusive).
    """

    def __init__(self, case_sensitive: bool = False) -> None:
        self._case_sensitive = case_sensitive

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def match(self, content: str, pattern: PatternDefinition) -> MatchResult | None:
        matches = self.match_all(content, pattern, max_matches=1)
        return matches[0] if matches else None

    def match_all(
        self,
        content: str,
        pattern: PatternDefinition,
        max_matches: int = 10,
    ) -> list[MatchResult]:
        if not content or not pattern.value:
            return []

        keyword = pattern.value

        # Case-insensitive: lowercase both content and keyword
        if not self._case_sensitive:
            search_content = content.lower()
            search_keyword = keyword.lower()
        else:
            search_content = content
            search_keyword = keyword

        try:
            automaton = self._build_automaton([search_keyword])
        except Exception:
            return []

        # ``find_matches_as_indexes`` returns ``list[tuple[int, int, int]]``
        # where each tuple is ``(match_id, start, end)``.
        raw = list(automaton.find_matches_as_indexes(search_content))
        if not raw:
            return []

        # Deduplicate overlapping / identical matches
        seen_ranges: set[tuple[int, int]] = set()
        results: list[MatchResult] = []
        count = 0

        for _match_id, start, end in raw:
            if count >= max_matches:
                break
            key = (start, end)
            if key in seen_ranges:
                continue
            seen_ranges.add(key)

            # Use the *original* content for extracted text
            matched_text = content[start:end]

            span = MatchSpan(
                start=start,
                end=end,
                matched=matched_text[:500],
                redacted=None,
            )
            results.append(
                MatchResult(
                    rule_id="",
                    pattern_index=count,
                    pattern_type="keyword",
                    pattern_value=keyword,
                    confidence=pattern.confidence,
                    spans=[span],
                    matched_text=matched_text[:200],
                )
            )
            count += 1

        return results

    def validate(self, pattern: PatternDefinition) -> None:
        if not pattern.value:
            raise ValueError("Keyword pattern value must not be empty")
        self._build_automaton([pattern.value])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_automaton(keywords: list[str]) -> ahocorasick_rs.AhoCorasick:
        """Build an Aho-Corasick automaton from a list of keywords."""
        return ahocorasick_rs.AhoCorasick(
            keywords,
            matchkind=ahocorasick_rs.MatchKind.Standard,
        )
