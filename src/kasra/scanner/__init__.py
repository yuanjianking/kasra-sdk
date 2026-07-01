"""Kasra Code Review Scanner — batch security scanning for code repositories.

The scanner loads rules from ``rules/code-review-rules.json`` and walks
a target directory, applying detection patterns to matching files.
"""

from kasra.scanner.scanner import CodeReviewScanner
from kasra.scanner.models import CodeReviewFinding, CodeReviewResult

__all__ = [
    "CodeReviewScanner",
    "CodeReviewFinding",
    "CodeReviewResult",
]
