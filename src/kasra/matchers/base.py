"""Kasra L3 Rule Engine — Abstract pattern matcher base."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from kasra.models.result import MatchResult, MatchSpan
from kasra.models.rule import PatternDefinition


class PatternMatcher(ABC):
    """Abstract base for all pattern matchers.

    Each matcher type (regex, keyword, entropy, composite) implements
    :meth:`match` and :meth:`match_all`. Subclasses are stateless where
    possible; any mutable cache is an instance-level LRU dict.
    """

    @abstractmethod
    def match(self, content: str, pattern: PatternDefinition) -> MatchResult | None:
        """Run a single pattern against *content*.

        Args:
            content: The text content to scan.
            pattern: The pattern definition (type, value, confidence, etc.).

        Returns:
            A ``MatchResult`` if the pattern matched, or ``None``.
        """
        ...

    def match_all(
        self,
        content: str,
        pattern: PatternDefinition,
        max_matches: int = 10,
    ) -> list[MatchResult]:
        """Return **all** non-overlapping matches for a pattern.

        The base implementation calls :meth:`match` and returns ``[result]``
        if matched. Override for matchers that can efficiently find multiple
        occurrences (e.g. keyword and regex with ``re.finditer``).
        """
        result = self.match(content, pattern)
        if result is not None:
            return [result]
        return []

    def validate(self, pattern: PatternDefinition) -> None:
        """Validate that the pattern definition is usable by this matcher.

        Raises:
            PatternCompileError: If the pattern value cannot be compiled.
        """
        _ = pattern.value  # default: just check it's non-empty
