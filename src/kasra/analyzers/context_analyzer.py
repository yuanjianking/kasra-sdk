"""Kasra L3 Rule Engine — Surrounding context analyzer.

Extracts text before and after each match position for evidence
chain building and cross-rule proximity correlation.
"""

from __future__ import annotations

from kasra.analyzers.base import Analyzer
from kasra.analyzers.context import AnalysisContext, CodeBlock, MatchContext


class SurroundingContextAnalyzer(Analyzer):
    """Extracts surrounding context around match positions.

    For each match, captures:
    - Text before the match (up to ``window`` chars)
    - Text after the match (up to ``window`` chars)
    - Whether the match is inside a code block
    - The code block's language if applicable
    """

    layer: int = 3
    name: str = "context_analyzer"

    def __init__(self, window: int = 200) -> None:
        super().__init__()
        self._window = window

    def analyze(self, content: str, context: AnalysisContext) -> AnalysisContext:
        """Context extraction runs per-match in :class:`RuleRunner`.

        This analyzer method is a no-op on the full content; context
        is extracted per-match during rule execution via :meth:`extract`.
        """
        return context

    def extract(
        self,
        content: str,
        match_start: int,
        match_end: int,
        code_blocks: list[CodeBlock] | None = None,
        window: int | None = None,
    ) -> MatchContext:
        """Extract surrounding context for a single match.

        Args:
            content: The full content string.
            match_start: Start offset of the match.
            match_end: End offset of the match.
            code_blocks: Optional list of code blocks for location check.
            window: Characters of context (defaults to instance window).

        Returns:
            A :class:`MatchContext` with surrounding text.
        """
        w = window or self._window
        content_len = len(content)

        # Extract before
        before_start = max(0, match_start - w)
        before = content[before_start:match_start].strip()

        # Extract after
        after_end = min(content_len, match_end + w)
        after = content[match_end:after_end].strip()

        # Code block detection
        is_in_block = False
        block_lang = None
        if code_blocks:
            for block in code_blocks:
                if block.start_char <= match_start < block.end_char:
                    is_in_block = True
                    block_lang = block.language
                    break

        return MatchContext(
            before=before,
            after=after,
            is_in_code_block=is_in_block,
            code_block_language=block_lang,
        )
