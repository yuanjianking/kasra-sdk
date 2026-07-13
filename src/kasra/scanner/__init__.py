"""Kasra Code Review Scanner — batch security scanning for code repositories.

Rules are injected via ``set_rules()`` (typically from the database).
The scanner then walks a target directory and applies detection patterns.
"""

from kasra.scanner.scanner import CodeReviewScanner
from kasra.scanner.models import CodeReviewFinding, CodeReviewResult

__all__ = [
    "CodeReviewScanner",
    "CodeReviewFinding",
    "CodeReviewResult",
]
