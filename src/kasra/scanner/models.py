"""Code review scanner — data models for findings and scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CodeReviewFinding:
    """A single code review finding from a rule match."""

    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    line_number: int
    column: int = 0
    matched_text: str = ""
    confidence: float = 0.0
    message: str = ""
    severity_context: str = ""


@dataclass
class CodeReviewResult:
    """Results from scanning a repository or directory."""

    scan_path: str
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[CodeReviewFinding] = field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def by_severity(self) -> dict[str, list[CodeReviewFinding]]:
        result: dict[str, list[CodeReviewFinding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result
