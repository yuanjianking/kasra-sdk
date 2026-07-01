"""Kasra L3 Rule Engine — Severity ordering utilities.

Provides a single source of truth for P0 / P1 / P2 rank mapping
so it is not duplicated across modules.
"""

from __future__ import annotations

from kasra.models.enums import Severity

# Ordered from most to least severe.
SEVERITY_RANK: dict[Severity, int] = {
    Severity.P0: 0,
    Severity.P1: 1,
    Severity.P2: 2,
}


def rank(severity: Severity) -> int:
    """Map a ``Severity`` enum to an integer rank (lower = more severe)."""
    return SEVERITY_RANK.get(severity, 99)


def is_more_severe(a: Severity, b: Severity) -> bool:
    """Return ``True`` if severity *a* is strictly more severe than *b*."""
    return rank(a) < rank(b)


def is_less_severe(a: Severity, b: Severity) -> bool:
    """Return ``True`` if severity *a* is strictly less severe than *b*."""
    return rank(a) > rank(b)
