"""Kasra L3 Rule Engine — Enumerations."""

from __future__ import annotations

from enum import Enum, auto


class Severity(str, Enum):
    """Severity levels for rule violations."""

    P0 = "P0"  # Critical — immediate block
    P1 = "P1"  # High — user-visible action required
    P2 = "P2"  # Medium — advisory / best practice


class ActionType(str, Enum):
    """Action types for matched rules."""

    BLOCK = "block"          # Reject the content outright
    WARN = "warn"            # Allow but attach warning to result
    REDACT = "redact"        # Sanitize the matched content in-place
    CLEAN = "clean"          # Normalize/clean content without redaction
    TRUNCATE = "truncate"    # Cut content at a boundary
    SOFT_ALLOW = "soft_allow"# Reduce severity to audit-only
    DYNAMIC = "dynamic"      # Action determined at runtime by context engine


class Stage(str, Enum):
    """Detection stage within the pipeline."""

    INPUT = "input"       # User → AI request
    OUTPUT = "output"     # AI → user response (streaming or complete)
    BATCH = "batch"       # File/directory scan
    BEHAVIOR = "behavior" # Session-level behavior monitoring


class PatternType(str, Enum):
    """Type of detection pattern."""

    REGEX = "regex"        # Regular expression pattern
    KEYWORD = "keyword"    # Exact keyword match (Aho-Corasick)
    ENTROPY = "entropy"    # Shannon entropy threshold (secret detection)
    COMPOSITE = "composite"# Combination of sub-patterns with logic


class MatchMode(str, Enum):
    """How multiple patterns in a rule are combined."""

    ANY = "any"  # Any pattern match triggers the rule (OR logic)
    ALL = "all"  # All patterns must match (AND logic)


class DetectionMode(str, Enum):
    """Detection mode for a pipeline stage."""

    REALTIME = "realtime"     # Instant: per-character/per-chunk fast path
    STREAMING = "streaming"   # Three-phase: chunk → boundary → end-of-stream
    SCAN = "scan"             # Full content: entire file or complete message
    MONITOR = "monitor"       # Session-level: tracks cumulative behavior


class PipelinePhase(str, Enum):
    """Phase of streaming detection (output pipeline)."""

    PHASE1_FAST = "phase1_fast"            # Per-chunk: regex + keyword only
    PHASE2_BOUNDARY = "phase2_boundary"    # At sentence/line boundary: full matchers
    PHASE3_END_OF_STREAM = "phase3_eos"    # End-of-stream: full content scan
