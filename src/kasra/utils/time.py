"""Kasra L3 Rule Engine — Time / timing utilities.

Centralises UTC timestamp generation and provides a lightweight
``Timer`` context manager for performance measurement.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Generator


def utcnow() -> datetime:
    """Return the current UTC datetime (timezone-aware).

    Shorthand for ``datetime.now(timezone.utc)``.  Use this everywhere
    instead of repeating the lambda so we have one import site.
    """
    return datetime.now(timezone.utc)


@contextmanager
def timer() -> Generator[_Timer, None, None]:
    """Context manager that measures elapsed wall-clock time.

    Usage::

        with timer() as t:
            do_something()
        print(f"Took {t.elapsed_ms:.1f} ms")
    """
    t = _Timer()
    t.start = time.perf_counter()
    try:
        yield t
    finally:
        t.end = time.perf_counter()


class _Timer:
    """Internal timer state exposed by the ``timer()`` context manager."""

    start: float = 0.0
    end: float = 0.0

    @property
    def elapsed_ms(self) -> float:
        return (self.end - self.start) * 1000
