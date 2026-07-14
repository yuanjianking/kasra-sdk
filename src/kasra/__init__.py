"""Kasra Rule Engine — AI Development Security Governance.

The Rule Engine is the core logic layer of the Kasra platform.
It receives content (user prompts, AI responses, files, session
behaviour), runs it through 200+ security rules across 10 rule
series, and returns detection results with appropriate actions.

Quick start::

    from kasra import RuleEngine

    engine = RuleEngine()
    engine.load_rules()

    result = engine.detect_input("my password is secret123")
    if result.blocked:
        print("Content was blocked")
    elif result.warnings:
        print("Warnings:", result.warnings)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from kasra._version import __version__
from kasra.config.global_config import GlobalConfig
from kasra.config.loader import ConfigLoader
from kasra.core.engine import RuleEngine

__all__ = [
    "__version__",
    "RuleEngine",
    "ConfigLoader",
    "GlobalConfig",
    "configure_rules",
]


# ---------------------------------------------------------------------------
# Convenience: one-shot configure() for simple use-cases
# ---------------------------------------------------------------------------

_global_engine: RuleEngine | None = None


def configure_rules(rules: list) -> RuleEngine:
    """Create and configure a global RuleEngine from a list of RuleDefinition objects.

    This is the preferred way to set up a RuleEngine in v0.4+ — the engine
    no longer reads rules from disk.

    Args:
        rules: A list of ``RuleDefinition`` objects.

    Returns:
        The configured ``RuleEngine`` instance (also stored globally).
    """
    global _global_engine
    _global_engine = RuleEngine()
    _global_engine.load_rules_from_list(rules)
    return _global_engine


# ---------------------------------------------------------------------------
# Convenience: one-shot configure() for simple use-cases
# ---------------------------------------------------------------------------

_global_engine: RuleEngine | None = None


def configure(
    *,
    rules_dir: str | os.PathLike | None = None,
    config_dir: str | os.PathLike | None = None,
    auto_load: bool = True,
    **config_overrides: Any,
) -> RuleEngine:
    """Create and configure a global ``RuleEngine`` singleton.

    This is a convenience for scripts and interactive use where a
    module-level singleton is acceptable.  For production, construct
    ``RuleEngine()`` directly — it is more explicit and testable.

    Args:
        rules_dir: Directory containing rule JSON bundles (used when
            *auto_load* is ``True``).
        config_dir: Directory containing YAML config files.
        auto_load: If ``True`` (default), read rules from JSON bundles
            in *rules_dir* and load them via ``load_rules_from_list()``.
        **config_overrides: Any ``GlobalConfig`` field to override
            (e.g. ``engine__max_concurrent_rules=50``).

    Returns:
        The configured ``RuleEngine`` instance (also stored globally).

    Usage::

        from kasra import configure

        engine = configure(
            rules_dir="./my-rules",
            auto_load=True,
            engine__max_concurrent_rules=10,
        )
        result = engine.detect_input("test")
    """
    global _global_engine

    config = GlobalConfig()
    key = ""
    for k, v in config_overrides.items():
        parts = k.lower().split("__")
        target = config
        for part in parts[:-1]:
            target = getattr(target, part)
        setattr(target, parts[-1], v)

    _global_engine = RuleEngine(
        config=config,
        rules_dir=rules_dir,
        config_dir=config_dir,
    )
    if auto_load:
        import warnings
        warnings.warn(
            "configure(auto_load=True) is a no-op in v0.4+ — "
            "the engine no longer reads rules from disk. "
            "Use load_rules_from_list() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
    return _global_engine


def configure_rules(rules: list) -> RuleEngine:
    """Create and configure a global RuleEngine from a list of RuleDefinition objects.

    Unlike ``configure()`` which reads from disk, this method accepts
    pre-built RuleDefinition objects — making it the preferred way to
    set up a RuleEngine in v0.4+.

    Args:
        rules: A list of ``RuleDefinition`` objects.

    Returns:
        The configured ``RuleEngine`` instance (also stored globally).
    """
    global _global_engine
    _global_engine = RuleEngine()
    _global_engine.load_rules_from_list(rules)
    return _global_engine


def get_engine() -> RuleEngine:
    """Return the global engine created by :func:`configure`.

    Raises:
        RuntimeError: If ``configure()`` has not been called yet.
    """
    if _global_engine is None:
        raise RuntimeError(
            "Global engine not configured. Call kasra.configure() first."
        )
    return _global_engine

