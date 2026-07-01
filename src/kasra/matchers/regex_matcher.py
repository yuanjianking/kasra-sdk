"""Kasra L3 Rule Engine — Regex matcher with LRU-cached compilation."""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from kasra.exceptions.errors import PatternCompileError
from kasra.matchers.base import PatternMatcher
from kasra.models.result import MatchResult, MatchSpan
from kasra.models.rule import PatternDefinition


class ReMatcher(PatternMatcher):
    """Regex pattern matcher with an LRU compile cache.

    Thread-safety notes:
      - ``re.compile`` is internally thread-safe.
      - The LRU cache is a plain ``OrderedDict``; in a multi-threaded
        scenario use ``self._cache`` under a lock or switch to
        ``functools.lru_cache`` which is thread-safe in CPython.
    """

    def __init__(self, cache_size: int = 1024) -> None:
        self._cache_size = cache_size
        self._cache: OrderedDict[str, re.Pattern[str]] = OrderedDict()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def match(self, content: str, pattern: PatternDefinition) -> MatchResult | None:
        if not content or not pattern.value:
            return None

        compiled = self._compile(pattern.value)
        match = compiled.search(content)
        if match is None:
            return None

        span = MatchSpan(
            start=match.start(),
            end=match.end(),
            matched=match.group()[:500],  # cap snippet length
            redacted=None,
        )

        return MatchResult(
            rule_id="",
            pattern_index=0,
            pattern_type="regex",
            pattern_value=pattern.value,
            confidence=pattern.confidence,
            spans=[span],
            matched_text=match.group()[:200],
        )

    def match_all(
        self,
        content: str,
        pattern: PatternDefinition,
        max_matches: int = 10,
    ) -> list[MatchResult]:
        if not content or not pattern.value:
            return []

        compiled = self._compile(pattern.value)
        results: list[MatchResult] = []
        count = 0

        for match in compiled.finditer(content):
            if count >= max_matches:
                break
            span = MatchSpan(
                start=match.start(),
                end=match.end(),
                matched=match.group()[:500],
                redacted=None,
            )
            results.append(
                MatchResult(
                    rule_id="",
                    pattern_index=count,
                    pattern_type="regex",
                    pattern_value=pattern.value,
                    confidence=pattern.confidence,
                    spans=[span],
                    matched_text=match.group()[:200],
                )
            )
            count += 1

        return results

    def validate(self, pattern: PatternDefinition) -> None:
        self._compile(pattern.value)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compile(self, pattern: str) -> re.Pattern[str]:
        """Get compiled regex from LRU cache or compile fresh."""
        if pattern in self._cache:
            self._cache.move_to_end(pattern)
            return self._cache[pattern]

        try:
            compiled = re.compile(pattern, re.UNICODE)
        except re.error as exc:
            raise PatternCompileError(f"Invalid regex: {pattern!r}: {exc}") from exc

        # LRU evict
        if len(self._cache) >= self._cache_size:
            self._cache.popitem(last=False)
        self._cache[pattern] = compiled
        return compiled
