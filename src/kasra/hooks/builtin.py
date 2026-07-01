"""Kasra L3 Rule Engine — Built-in plugin hooks.

Provides built-in hook implementations that ship with the engine.
Users can enable/disable them via config or register custom hooks.

Available hooks:
  - ``MetricsCollector`` — records detection latency and trigger counts.
  - ``AuditEnricher`` — enriches audit events with additional context.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from kasra.hooks.base import Hook
from kasra.models.context import RequestContext
from kasra.models.result import AggregatedResult, DetectionResult


class MetricsCollector(Hook):
    """Collects detection metrics: latency, trigger counts, rule hit rates.

    Stores metrics in-memory.  Export via :meth:`snapshot`.

    Usage::

        registry = HookRegistry()
        registry.register(MetricsCollector())

        # Later:
        metrics = registry.hooks[0].snapshot()
        print(metrics["total_detections"])
    """

    def __init__(self) -> None:
        super().__init__()
        self._total_detections = 0
        self._total_latency_ms = 0.0
        self._trigger_counts: Counter[str] = Counter()
        self._rule_latency: dict[str, list[float]] = {}
        self._last_detect_start: float = 0.0
        self._last_rule_start: float = 0.0

    # ------------------------------------------------------------------
    # Hook overrides
    # ------------------------------------------------------------------

    def before_detect(self, content: str, context: RequestContext | None = None) -> None:
        self._last_detect_start = time.perf_counter()

    def after_detect(self, result: AggregatedResult, context: RequestContext | None = None) -> None:
        self._total_detections += 1
        if result.execution_time_ms:
            self._total_latency_ms += result.execution_time_ms
        for dr in result.triggered_rules:
            self._trigger_counts[dr.rule_id] += 1

    def before_rule(self, rule_id: str, content: str, context: RequestContext | None = None) -> None:
        self._last_rule_start = time.perf_counter()

    def after_rule(self, result: DetectionResult, context: RequestContext | None = None) -> None:
        elapsed = (time.perf_counter() - self._last_rule_start) * 1000
        if result.rule_id not in self._rule_latency:
            self._rule_latency[result.rule_id] = []
        self._rule_latency[result.rule_id].append(elapsed)

    # ------------------------------------------------------------------
    # Metrics export
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Return a snapshot of collected metrics."""
        avg_latency = self._total_latency_ms / max(1, self._total_detections)

        rule_stats = {}
        for rule_id, latencies in self._rule_latency.items():
            rule_stats[rule_id] = {
                "calls": len(latencies),
                "avg_ms": round(sum(latencies) / len(latencies), 2),
                "max_ms": round(max(latencies), 2),
            }

        return {
            "total_detections": self._total_detections,
            "avg_latency_ms": round(avg_latency, 2),
            "total_latency_ms": round(self._total_latency_ms, 2),
            "trigger_counts": dict(self._trigger_counts.most_common(20)),
            "rule_stats": rule_stats,
        }

    def reset(self) -> None:
        """Reset all collected metrics."""
        self._total_detections = 0
        self._total_latency_ms = 0.0
        self._trigger_counts.clear()
        self._rule_latency.clear()
