"""Kasra L3 Rule Engine — Chunk boundary detector for streaming output.

The :class:`BoundaryDetector` identifies natural boundaries (sentence end,
line end, paragraph break) in streaming text so that the output pipeline
can flush a completed segment for full detection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


_SENTENCE_END = re.compile(r"(?<=[.?!])\s+(?=[A-Z\"'(\\[{])")
_PARAGRAPH_BREAK = re.compile(r"\n\s*\n")


@dataclass(frozen=True)
class Boundary:
    """A detected boundary in the stream."""

    position: int
    boundary_type: str  # "sentence", "line", "paragraph", "hard_flush"


class BoundaryDetector:
    """Identifies natural flush boundaries in streaming content.

    Modes:
        - ``sentence``: flush after sentence-ending punctuation (. ? !) followed
          by whitespace and a capital letter or quote.
        - ``line``: flush after each ``\\n``.
        - ``paragraph``: flush after blank line (``\\n\\s*\\n``).
        - ``word``: flush after any whitespace boundary.
    """

    def __init__(self, mode: str = "sentence", min_chars: int = 50) -> None:
        self._mode = mode
        self._min_chars = min_chars

    def find_boundaries(self, text: str, offset: int = 0) -> list[Boundary]:
        """Return all boundaries found in *text*, shifted by *offset*.

        Args:
            text: The text to scan for boundaries.
            offset: Position offset to add (used when scanning a sliding window).

        Returns:
            A list of ``Boundary`` dataclass instances, sorted by position.
        """
        boundaries: list[Boundary] = []

        if self._mode == "sentence":
            for match in _SENTENCE_END.finditer(text):
                pos = match.start() + 1
                if pos >= self._min_chars:
                    boundaries.append(Boundary(pos + offset, "sentence"))

        elif self._mode == "paragraph":
            for match in _PARAGRAPH_BREAK.finditer(text):
                pos = match.end()
                if pos >= self._min_chars:
                    boundaries.append(Boundary(pos + offset, "paragraph"))

        elif self._mode == "line":
            for i, ch in enumerate(text):
                if ch == "\n" and i >= self._min_chars:
                    boundaries.append(Boundary(i + offset, "line"))

        elif self._mode == "word":
            for i, ch in enumerate(text):
                if ch.isspace() and i >= self._min_chars:
                    boundaries.append(Boundary(i + offset, "word"))

        return boundaries

    def last_boundary_before(self, text: str, max_pos: int) -> Boundary | None:
        """Find the last boundary at or before *max_pos*.

        Returns ``None`` if no boundary was found or if *max_pos* is below
        ``min_chars``.
        """
        if max_pos < self._min_chars:
            return None
        boundaries = self.find_boundaries(text)
        candidates = [b for b in boundaries if b.position <= max_pos]
        return candidates[-1] if candidates else None
