"""Kasra L3 Rule Engine — Chunk buffer for streaming detection.

The :class:`ChunkBuffer` maintains a sliding window of streaming content
so that the output pipeline can:

  - Accumulate chunks until a flush boundary is reached.
  - Maintain context for retroactive redaction.
  - Provide a complete view for end-of-stream full scanning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ChunkBuffer:
    """Sliding-window buffer for streaming content.

    The buffer accumulates chunks as they arrive.  When ``flush_ready``
    returns a boundary position the caller can pop the completed prefix
    (via ``pop_flushed``) for full detection.

    Design:
      - ``_buffer`` holds the entire stream so far.
      - ``_flushed_pos`` marks how much has already been flushed to the
        detection pipeline; everything before it has been seen.
      - ``_byte_count`` tracks the total size for the caller's convenience.
    """

    max_size: int = 1_000_000  # 1M chars — safety limit
    boundary_detector: Callable[[str], int | None] | None = None

    _buffer: list[str] = field(default_factory=list)
    _flushed_pos: int = 0
    _total_chars: int = 0
    _is_complete: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, chunk: str) -> None:
        """Append a chunk to the buffer.

        Args:
            chunk: Text chunk from the stream.

        Raises:
            RuntimeError: If the buffer exceeds ``max_size``.
        """
        if self._is_complete:
            return

        self._buffer.append(chunk)
        self._total_chars += len(chunk)

        if self._total_chars > self.max_size:
            raise RuntimeError(
                f"ChunkBuffer exceeded max_size ({self.max_size}) — "
                f"stream too long without flush"
            )

    def mark_complete(self) -> None:
        """Mark the stream as complete (end-of-stream)."""
        self._is_complete = True

    @property
    def content(self) -> str:
        """Return the full buffered content."""
        return "".join(self._buffer)

    @property
    def unflushed(self) -> str:
        """Return content that has not yet been flushed to detection."""
        full = self.content
        return full[self._flushed_pos :]

    @property
    def flushed_pos(self) -> int:
        return self._flushed_pos

    @property
    def is_complete(self) -> bool:
        return self._is_complete

    @property
    def total_chars(self) -> int:
        return self._total_chars

    def flush_ready(self) -> int | None:
        """Return the position up to which content is ready to flush.

        If a ``boundary_detector`` is set, it is called with the unflushed
        content.  If it returns a position the caller should flush up to
        ``flushed_pos + position``.

        If no detector is set, returns ``total_chars`` when the stream is
        complete (end-of-stream flush), otherwise ``None``.
        """
        if self._is_complete:
            return self._total_chars

        if self.boundary_detector is not None:
            boundary = self.boundary_detector(self.unflushed)
            if boundary is not None:
                return self._flushed_pos + boundary

        return None

    def pop_flushed(self, up_to: int) -> str:
        """Pop and return content up to *up_to*.

        After calling this, ``flushed_pos`` advances, and the internal
        buffer list is trimmed to free memory.

        Args:
            up_to: Absolute character position to flush up to (exclusive).

        Returns:
            The flushed content segment.
        """
        full = self.content
        segment = full[self._flushed_pos : up_to]
        self._flushed_pos = up_to

        # Trim the buffer list to free memory
        # We keep only what's after flushed_pos
        remaining = full[up_to:]
        self._buffer = [remaining] if remaining else []
        self._total_chars = len(remaining)

        return segment

    def reset(self) -> None:
        """Clear the buffer entirely."""
        self._buffer.clear()
        self._flushed_pos = 0
        self._total_chars = 0
        self._is_complete = False
