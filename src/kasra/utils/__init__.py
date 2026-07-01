"""Kasra L3 Rule Engine — Shared utility modules.

Intended for cross-module helpers that don't belong to any single
package: severity ordering, timestamp generation, text normalisation,
lazy / optional imports, and the like.

Usage::

    from kasra.utils.severity import SEVERITY_RANK, is_more_severe
    from kasra.utils.time import utcnow, timer
    from kasra.utils.text import normalize_text, truncate_at_boundary
    from kasra.utils.imports import lazy_import, optional_import
"""

from __future__ import annotations

from kasra.utils.imports import lazy_import, optional_import
from kasra.utils.severity import SEVERITY_RANK, is_less_severe, is_more_severe, rank
from kasra.utils.text import (
    _INVISIBLE_CHARS,
    nfc_normalize,
    normalize_text,
    strip_control,
    strip_invisible,
    truncate_at_boundary,
)
from kasra.utils.time import timer, utcnow

__all__ = [
    # severity
    "SEVERITY_RANK",
    "rank",
    "is_more_severe",
    "is_less_severe",
    # time
    "utcnow",
    "timer",
    # text
    "_INVISIBLE_CHARS",
    "strip_invisible",
    "strip_control",
    "nfc_normalize",
    "normalize_text",
    "truncate_at_boundary",
    # imports
    "lazy_import",
    "optional_import",
]
