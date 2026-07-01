"""Kasra L3 Rule Engine — Language-specific analysis.

Adjusts detection confidence based on whether the detected programming
language matches the language expected by a rule.

For example, if a rule targets Python-specific dangerous functions
(``eval``, ``exec``) and the content is detected as JavaScript, the
confidence is lowered because the same text patterns may appear in
JavaScript code with different semantics.
"""

from __future__ import annotations

from kasra.analyzers.base import Analyzer
from kasra.analyzers.context import AnalysisContext


# Language-family similarity groups.
# If a rule targets one language in a group, all members of that group
# are considered a partial match.
_LANGUAGE_FAMILIES: dict[str, set[str]] = {
    "c_like": {"cpp", "csharp", "java", "kotlin", "javascript", "typescript", "go"},
    "scripting": {"python", "ruby", "php", "javascript", "typescript", "bash", "powershell"},
    "functional": {"python", "javascript", "typescript", "kotlin", "swift", "rust"},
    "pythonic": {"python", "ruby"},
    "jvm": {"java", "kotlin"},
    "dotnet": {"csharp"},
    "web": {"javascript", "typescript", "php", "python"},
    "systems": {"rust", "cpp", "go"},
    "data": {"python", "sql", "r"},
}


class LanguageSpecificAnalyzer(Analyzer):
    """Adjust detection confidence based on language-rule alignment.

    This analyzer is invoked per-rule during matching, not as a
    pre-processing step.
    """

    layer: int = 3
    name: str = "language_specific"

    def analyze(self, content: str, context: AnalysisContext) -> AnalysisContext:
        """Language-specific adjustment runs per-rule in :class:`RuleRunner`."""
        return context

    def adjust_confidence(
        self,
        base_confidence: float,
        rule_languages: list[str] | None,
        detected_language: str | None,
        detected_confidence: float,
    ) -> float:
        """Adjust *base_confidence* based on language alignment.

        Args:
            base_confidence: The original confidence from the pattern match.
            rule_languages: Languages this rule targets (from ``DetectionConfig.languages``).
            detected_language: Language detected in the content.
            detected_confidence: Confidence of the language detection.

        Returns:
            Adjusted confidence (0.0–1.0).
        """
        if not rule_languages or not detected_language:
            return base_confidence  # No adjustment needed

        if detected_confidence < 0.3:
            return base_confidence  # Language detection too uncertain

        # Exact match — full confidence
        if detected_language in rule_languages:
            return base_confidence

        # Family match — slight reduction
        for family, members in _LANGUAGE_FAMILIES.items():
            if detected_language in members and any(lang in members for lang in rule_languages):
                return base_confidence * 0.85

        # No match — significant reduction
        return base_confidence * 0.5
