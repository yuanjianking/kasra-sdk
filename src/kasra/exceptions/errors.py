"""Kasra L3 Rule Engine — Exception hierarchy."""

from __future__ import annotations


class KasraError(Exception):
    """Base exception for all Kasra L3 Rule Engine errors."""


class RuleLoadError(KasraError):
    """Raised when a rule definition cannot be loaded or validated."""


class RuleNotFoundError(KasraError):
    """Raised when a requested rule ID does not exist in the store."""


class ConfigError(KasraError):
    """Raised when configuration is invalid or missing."""


class MatcherError(KasraError):
    """Raised when a matcher encounters an error during pattern matching."""


class PatternCompileError(MatcherError):
    """Raised when a regex or other pattern cannot be compiled."""


class ActionError(KasraError):
    """Raised when an action executor fails."""


class PipelineError(KasraError):
    """Raised during pipeline execution."""


class AuditError(KasraError):
    """Raised when audit logging fails."""


class HookError(KasraError):
    """Raised when a plugin hook encounters an error."""


class NormalizationError(KasraError):
    """Raised when input normalization fails."""
