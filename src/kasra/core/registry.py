"""Kasra L3 Rule Engine — Rule registry.

The :class:`RuleRegistry` builds efficient, priority-ordered indexes over
the rules in a ``RuleStore`` so that pipelines can quickly retrieve the
right rules for a given stage without scanning the full store each time.
"""

from __future__ import annotations

from collections import defaultdict

from kasra.models.enums import Severity, Stage
from kasra.models.rule import RuleDefinition
from kasra.rules.store import RuleStore
from kasra.utils.severity import SEVERITY_RANK


class RuleRegistry:
    """Organises rules for fast pipeline access.

    The registry wraps a ``RuleStore`` and adds:
      - Stage-indexed, severity-ordered rule lists.
      - Caching of frequently-accessed subsets.
      - Manual rebuild trigger (``rebuild()``) called after store changes.
    """

    def __init__(self, store: RuleStore | None = None) -> None:
        self._store = store
        # Index: stage -> [severity_rank -> [RuleDefinition]]
        self._by_stage: dict[str, dict[int, list[RuleDefinition]]] = {}
        self._needs_rebuild = True

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def set_store(self, store: RuleStore) -> None:
        """Set or swap the underlying rule store."""
        self._store = store
        self._needs_rebuild = True

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_rules_for_stage(
        self,
        stage: str | Stage,
        only_enabled: bool = True,
    ) -> list[RuleDefinition]:
        """Return rules applicable to *stage*, ordered P0 → P1 → P2.

        Args:
            stage: The pipeline stage to filter by.
            only_enabled: If ``True`` (default), only enabled rules are returned.

        Returns:
            A list of ``RuleDefinition`` objects.
        """
        self._maybe_rebuild()
        stage_val = stage.value if isinstance(stage, Stage) else stage
        ranked = self._by_stage.get(stage_val)
        if ranked is None:
            return []

        result: list[RuleDefinition] = []
        for rank in sorted(ranked):
            for rule in ranked[rank]:
                if only_enabled and not rule.enabled:
                    continue
                result.append(rule)
        return result

    def get_rules_by_severity(self, severity: Severity) -> list[RuleDefinition]:
        """Return all rules with a given severity."""
        self._maybe_rebuild()
        if self._store is None:
            return []
        return self._store.get_by_severity(severity)

    def count_by_stage(self, stage: str | Stage) -> int:
        """Return the number of rules applicable to *stage*."""
        return len(self.get_rules_for_stage(stage))

    def get_rule(self, rule_id: str) -> RuleDefinition:
        """Retrieve a single rule by ID (delegates to store)."""
        if self._store is None:
            raise ValueError("No RuleStore configured")
        return self._store.get(rule_id)

    def all_rules(self) -> list[RuleDefinition]:
        """Return all rules (delegates to store)."""
        if self._store is None:
            return []
        return self._store.all()

    # ------------------------------------------------------------------
    # Rebuild
    # ------------------------------------------------------------------

    def rebuild(self) -> None:
        """Explicitly rebuild all indexes.

        Called automatically on the first query after a store change.
        """
        self._by_stage.clear()
        if self._store is None:
            self._needs_rebuild = False
            return

        for stage_str in ("input", "output", "batch", "behavior"):
            ranked: dict[int, list[RuleDefinition]] = defaultdict(list)
            for rule in self._store.get_by_stage(stage_str):
                rank = SEVERITY_RANK.get(rule.severity, 99)
                ranked[rank].append(rule)
            self._by_stage[stage_str] = dict(ranked)

        self._needs_rebuild = False

    def _maybe_rebuild(self) -> None:
        """Rebuild indexes if the store has changed."""
        if self._needs_rebuild:
            self.rebuild()
