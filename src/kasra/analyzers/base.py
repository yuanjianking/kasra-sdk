"""Kasra L3 Rule Engine — Analyzer base class and pipeline orchestrator.

The :class:`Analyzer` is the abstract base for all 5-layer analyzers.
The :class:`AnalyzerPipeline` orchestrates them in dependency order.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from kasra.analyzers.context import AnalysisContext


class Analyzer(ABC):
    """Base class for all content analyzers across the 5 detection layers.

    Each analyzer enriches the shared :class:`AnalysisContext`.
    Analyzers are ordered by layer; within a layer they run in
    dependency order specified by :meth:`get_dependencies`.
    """

    layer: int = 2
    """Layer number (1 = lexical, 2 = syntactic, 3 = semantic, 4 = correlation, 5 = external)."""

    name: str = ""
    """Unique analyzer name for logging and dependency resolution."""

    def __init__(self) -> None:
        if not self.name:
            self.name = type(self).__name__

    @abstractmethod
    def analyze(self, content: str, context: AnalysisContext) -> AnalysisContext:
        """Analyse *content* and enrich *context*.

        Args:
            content: The full raw content string.
            context: The mutable context, pre-populated by earlier layers.

        Returns:
            The enriched context (the same object, mutated in-place).
        """
        ...

    def get_dependencies(self) -> list[str]:
        """Return names of analyzers that must run before this one."""
        return []


class AnalyzerPipeline:
    """Orchestrates the 5-layer analyzer pipeline.

    Runs all registered analyzers in dependency order, grouped by layer.
    Layer 1 (Lexical) is handled by the existing
    :class:`~kasra.matchers.base.PatternMatcher` instances and is not
    part of this pipeline.

    Usage::

        pipeline = AnalyzerPipeline.create_default()
        context = pipeline.execute("some python code: eval(x)")
        print(context.detected_language)  # "python"
    """

    def __init__(self, analyzers: list[Analyzer] | None = None) -> None:
        self._analyzers = analyzers or []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, content: str) -> AnalysisContext:
        """Run all analyzers in order against *content*.

        Args:
            content: The content to analyse.

        Returns:
            A fully populated :class:`AnalysisContext`.
        """
        context = AnalysisContext(content=content)
        for analyzer in self._analyzers:
            try:
                context = analyzer.analyze(content, context)
            except Exception:
                # Analyzers must never crash the pipeline
                import logging
                logging.getLogger("kasra.analyzers").exception(
                    "Analyzer %s failed", analyzer.name
                )
        return context

    def add_analyzer(self, analyzer: Analyzer) -> None:
        """Register an additional analyzer."""
        self._analyzers.append(analyzer)

    @property
    def analyzers(self) -> list[Analyzer]:
        """Read-only list of registered analyzers."""
        return list(self._analyzers)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create_default(cls) -> AnalyzerPipeline:
        """Create a pipeline with all built-in analyzers.

        Includes:
          Layer 2 — LanguageDetector, CodeBlockAnalyzer
          Layer 3 — LuhnValidator, SurroundingContextAnalyzer,
                    LanguageSpecificAnalyzer, DataFlowAnalyzer

        Layer 4 (correlation) and Layer 5 (external) are invoked
        separately from :meth:`DetectionPipeline._aggregate` and
        are not included here by default.
        """
        from kasra.analyzers.language_detector import LanguageDetector
        from kasra.analyzers.code_block_analyzer import CodeBlockAnalyzer
        from kasra.analyzers.data_flow_analyzer import DataFlowAnalyzer
        from kasra.analyzers.context_analyzer import SurroundingContextAnalyzer
        from kasra.analyzers.language_specific import LanguageSpecificAnalyzer

        return cls([
            # Layer 2: Syntactic
            LanguageDetector(),
            CodeBlockAnalyzer(),
            # Layer 3: Semantic
            SurroundingContextAnalyzer(),
            DataFlowAnalyzer(),
            LanguageSpecificAnalyzer(),
        ])
