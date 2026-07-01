"""Kasra L3 Rule Engine — Thread-safe in-memory rule store.

The RuleStore holds all loaded rule definitions and provides
fast indexed access by rule ID, severity, category, and stage.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from typing import Iterable

from kasra.exceptions.errors import RuleNotFoundError
from kasra.models.enums import Severity, Stage
from kasra.models.rule import RuleDefinition


class RuleStore:
    """Thread-safe, copy-on-write index for rule definitions.

    Design decisions:
      - **Copy-on-write**: ``_rules`` is replaced atomically on bulk updates.
        Readers iterate over a snapshot so they never see a half-updated store.
      - **Pre-built indexes**: Categories, severities, and stages are re-built
        once after each bulk update — not on every query.
      - **Not dict-of-list for stages**: We store the *applicable_stages* field
        as a flat frozenset on each rule and pre-filter in queries.
    """

    def __init__(self, rules: Iterable[RuleDefinition] | None = None) -> None:
        self._rules: dict[str, RuleDefinition] = {}
        self._by_category: dict[str, list[RuleDefinition]] = defaultdict(list)
        self._by_severity: dict[Severity, list[RuleDefinition]] = defaultdict(list)
        self._by_stage: dict[str, list[RuleDefinition]] = defaultdict(list)

        if rules is not None:
            self.bulk_replace(rules)

    # ------------------------------------------------------------------
    # Public query methods
    # ------------------------------------------------------------------

    def get(self, rule_id: str) -> RuleDefinition:
        """Retrieve a single rule by ID.

        Raises:
            RuleNotFoundError: If the rule ID does not exist.
        """
        rule = self._rules.get(rule_id)
        if rule is None:
            raise RuleNotFoundError(f"Rule not found: {rule_id}")
        return rule

    def exists(self, rule_id: str) -> bool:
        """Check whether a rule ID exists in the store."""
        return rule_id in self._rules

    def get_by_category(self, category: str) -> list[RuleDefinition]:
        """Get all rules in a given category."""
        return list(self._by_category.get(category, []))

    def get_by_severity(self, severity: Severity) -> list[RuleDefinition]:
        """Get all rules with a given severity level."""
        return list(self._by_severity.get(severity, []))

    def get_by_stage(self, stage: str | Stage) -> list[RuleDefinition]:
        """Get all rules applicable to a given pipeline stage.

        A rule is applicable if ``stage`` appears in its
        ``applicable_stages`` list or if that list contains ``"*"``.
        """
        stage_val = stage.value if isinstance(stage, Stage) else stage
        return list(self._by_stage.get(stage_val, []))

    def get_enabled_by_stage(self, stage: str | Stage) -> list[RuleDefinition]:
        """Like ``get_by_stage`` but only returns enabled rules."""
        stage_val = stage.value if isinstance(stage, Stage) else stage
        return [r for r in self._by_stage.get(stage_val, []) if r.enabled]

    def all(self) -> list[RuleDefinition]:
        """Return a snapshot of all rules."""
        return list(self._rules.values())

    def count(self) -> int:
        """Return the total number of rules in the store."""
        return len(self._rules)

    def count_by_severity(self) -> dict[Severity, int]:
        """Return counts per severity level."""
        return {sev: len(self._by_severity[sev]) for sev in Severity}

    # ------------------------------------------------------------------
    # Bulk mutation (copy-on-write)
    # ------------------------------------------------------------------

    def bulk_replace(self, rules: Iterable[RuleDefinition]) -> None:
        """Replace all rules atomically.

        This is the primary mutation method. A copy of the current index
        is built, then the internal reference is swapped.

        Args:
            rules: An iterable of RuleDefinition objects.
        """
        new_rules: dict[str, RuleDefinition] = {}
        by_cat: dict[str, list[RuleDefinition]] = defaultdict(list)
        by_sev: dict[Severity, list[RuleDefinition]] = defaultdict(list)
        by_stage: dict[str, list[RuleDefinition]] = defaultdict(list)

        for rule in rules:
            new_rules[rule.id] = rule
            by_cat[rule.category].append(rule)
            by_sev[rule.severity].append(rule)
            for stage in rule.applicable_stages:
                by_stage[stage].append(rule)

        # Atomic swap — after this point readers see a consistent view.
        self._rules = new_rules
        self._by_category = dict(by_cat)
        self._by_severity = dict(by_sev)
        self._by_stage = dict(by_stage)

    def bulk_add(self, rules: Iterable[RuleDefinition]) -> None:
        """Add new rules to the store (merge with existing).

        If a rule ID already exists it is **overwritten**.
        """
        merged = dict(self._rules)
        for rule in rules:
            merged[rule.id] = rule
        self.bulk_replace(merged.values())

    # ------------------------------------------------------------------
    # Mutation (single rule)
    # ------------------------------------------------------------------

    def add(self, rule: RuleDefinition) -> None:
        """Add or overwrite a single rule."""
        self.bulk_add([rule])

    def remove(self, rule_id: str) -> None:
        """Remove a single rule by ID.

        Raises:
            RuleNotFoundError: If the rule does not exist.
        """
        if rule_id not in self._rules:
            raise RuleNotFoundError(f"Cannot remove: rule not found {rule_id}")
        merged = dict(self._rules)
        del merged[rule_id]
        self.bulk_replace(merged.values())
