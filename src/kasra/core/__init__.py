"""Core engine: registry, runner, pipeline, engine."""

from kasra.core.engine import RuleEngine
from kasra.core.pipeline import DetectionPipeline
from kasra.core.registry import RuleRegistry
from kasra.core.runner import MatcherDispatcher, RuleRunner

__all__ = [
    "RuleEngine",
    "DetectionPipeline",
    "RuleRegistry",
    "RuleRunner",
    "MatcherDispatcher",
]
