"""Unit tests for rules/store, core/registry, exceptions, and rule engine."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from kasra.rules.store import RuleStore
from kasra.core.registry import RuleRegistry
from kasra.core.engine import RuleEngine
from kasra.exceptions.errors import RuleLoadError, RuleNotFoundError
from kasra.models.enums import Severity
from kasra.models.rule import RuleDefinition


# ======================================================================
# RuleStore
# ======================================================================

class TestRuleStore:
    def make_rules(self, n=3):
        return [
            RuleDefinition(
                id=f"I-{i:02d}", name=f"Rule {i}", description="test",
                category="credential_leak" if i % 2 == 0 else "injection",
                severity=Severity.P0 if i == 1 else Severity.P1,
                action="block" if i == 1 else "warn",
                applicable_stages=["input"],
            )
            for i in range(1, n + 1)
        ]

    def test_empty_store(self):
        store = RuleStore()
        assert store.count() == 0
        assert store.all() == []

    def test_bulk_replace(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules(3))
        assert store.count() == 3

    def test_get_by_id(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules(3))
        rule = store.get("I-01")
        assert rule.id == "I-01"

    def test_get_by_id_not_found(self):
        store = RuleStore()
        with pytest.raises(RuleNotFoundError):
            store.get("NONEXISTENT")

    def test_exists(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules(1))
        assert store.exists("I-01") is True
        assert store.exists("I-99") is False

    def test_get_by_category(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules(4))
        cred = store.get_by_category("credential_leak")
        inj = store.get_by_category("injection")
        assert len(cred) >= 1
        assert len(inj) >= 1

    def test_get_by_severity(self):
        store = RuleStore()
        rules = self.make_rules(3)
        store.bulk_replace(rules)
        p0 = store.get_by_severity(Severity.P0)
        assert len(p0) == 1

    def test_get_by_stage(self):
        store = RuleStore()
        rules = self.make_rules(2)
        rules[0].applicable_stages = ["input"]
        rules[1].applicable_stages = ["output"]
        store.bulk_replace(rules)
        assert len(store.get_by_stage("input")) == 1
        assert len(store.get_by_stage("output")) == 1
        assert len(store.get_by_stage("batch")) == 0

    def test_get_enabled_by_stage(self):
        store = RuleStore()
        rules = self.make_rules(2)
        rules[0].enabled = True
        rules[1].enabled = False
        rules[0].applicable_stages = ["input"]
        rules[1].applicable_stages = ["input"]
        store.bulk_replace(rules)
        assert len(store.get_enabled_by_stage("input")) == 1

    def test_bulk_add(self):
        store = RuleStore()
        store.bulk_add(self.make_rules(2))
        assert store.count() == 2
        store.bulk_add(self.make_rules(2))  # Same IDs → overwrite
        assert store.count() == 2

    def test_add(self):
        store = RuleStore()
        rule = self.make_rules(1)[0]
        store.add(rule)
        assert store.count() == 1

    def test_remove(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules(2))
        store.remove("I-01")
        assert store.count() == 1
        assert store.exists("I-01") is False

    def test_remove_not_found(self):
        store = RuleStore()
        with pytest.raises(RuleNotFoundError):
            store.remove("NONEXISTENT")

    def test_count_by_severity(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules(3))
        counts = store.count_by_severity()
        total = sum(counts.values())
        assert total == 3

    def test_atomic_replace(self):
        """bulk_replace is atomic — new dict swapped in after full construction."""
        store = RuleStore()
        store.bulk_replace(self.make_rules(3))
        snapshot = store.all()
        store.bulk_replace(self.make_rules(5))
        assert len(snapshot) == 3


# ======================================================================
# RuleRegistry
# ======================================================================

class TestRuleRegistry:
    def make_rules(self):
        return [
            RuleDefinition(
                id="I-01", name="A", description="test",
                category="test", severity=Severity.P0, action="block",
                applicable_stages=["input"],
            ),
            RuleDefinition(
                id="I-02", name="B", description="test",
                category="test", severity=Severity.P1, action="warn",
                applicable_stages=["input"],
            ),
            RuleDefinition(
                id="O-01", name="C", description="test",
                category="test", severity=Severity.P2, action="warn",
                applicable_stages=["output"],
            ),
        ]

    def test_empty_registry(self):
        reg = RuleRegistry()
        assert reg.get_rules_for_stage("input") == []
        assert reg.all_rules() == []

    def test_set_store(self):
        reg = RuleRegistry()
        store = RuleStore()
        store.bulk_replace(self.make_rules())
        reg.set_store(store)
        rules = reg.get_rules_for_stage("input")
        assert len(rules) == 2

    def test_get_rules_for_stage(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules())
        reg = RuleRegistry(store)
        input_rules = reg.get_rules_for_stage("input")
        output_rules = reg.get_rules_for_stage("output")
        assert len(input_rules) == 2
        assert len(output_rules) == 1

    def test_get_rules_for_stage_ordering(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules())
        reg = RuleRegistry(store)
        rules = reg.get_rules_for_stage("input")
        assert len(rules) == 2
        assert rules[0].id == "I-01"
        assert rules[1].id == "I-02"

    def test_get_rules_for_stage_only_enabled(self):
        store = RuleStore()
        rules = self.make_rules()
        rules[1].enabled = False
        store.bulk_replace(rules)
        reg = RuleRegistry(store)
        rules = reg.get_rules_for_stage("input")
        assert len(rules) == 1
        rules_all = reg.get_rules_for_stage("input", only_enabled=False)
        assert len(rules_all) == 2

    def test_get_rules_by_severity(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules())
        reg = RuleRegistry(store)
        p0 = reg.get_rules_by_severity(Severity.P0)
        assert len(p0) == 1
        assert p0[0].id == "I-01"

    def test_count_by_stage(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules())
        reg = RuleRegistry(store)
        assert reg.count_by_stage("input") == 2
        assert reg.count_by_stage("output") == 1

    def test_get_rule(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules())
        reg = RuleRegistry(store)
        rule = reg.get_rule("I-01")
        assert rule.id == "I-01"

    def test_get_rule_no_store(self):
        reg = RuleRegistry()
        with pytest.raises(ValueError):
            reg.get_rule("I-01")

    def test_all_rules(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules())
        reg = RuleRegistry(store)
        assert len(reg.all_rules()) == 3

    def test_rebuild(self):
        store = RuleStore()
        store.bulk_replace(self.make_rules())
        reg = RuleRegistry(store)
        new_rules = self.make_rules() + [
            RuleDefinition(
                id="O-02", name="D", description="test",
                category="test", severity=Severity.P0, action="block",
                applicable_stages=["output"],
            ),
        ]
        store.bulk_replace(new_rules)
        reg.rebuild()
        assert reg.count_by_stage("output") == 2


# ======================================================================
# RuleEngine — load_rules_from_list
# ======================================================================

class TestRuleEngineLoad:
    def make_rules(self, n=3):
        return [
            RuleDefinition(
                id=f"I-{i:02d}", name=f"Rule {i}", description="test",
                category="test", severity=Severity.P1, action="warn",
                applicable_stages=["input"],
            )
            for i in range(1, n + 1)
        ]

    def test_load_rules_from_list(self):
        engine = RuleEngine()
        count = engine.load_rules_from_list(self.make_rules(3))
        assert count == 3
        assert engine.rule_count == 3
        assert engine.is_loaded

    def test_load_rules_from_list_empty(self):
        engine = RuleEngine()
        count = engine.load_rules_from_list([])
        assert count == 0
        assert engine.is_loaded

    def test_load_rules_multiple_calls(self):
        engine = RuleEngine()
        engine.load_rules_from_list(self.make_rules(2))
        engine.load_rules_from_list(self.make_rules(5))
        assert engine.rule_count == 5

    def test_rule_count_property(self):
        engine = RuleEngine()
        assert engine.rule_count == 0
        assert not engine.is_loaded
        engine.load_rules_from_list(self.make_rules(2))
        assert engine.rule_count == 2
        assert engine.is_loaded

    def test_store_has_rules_after_load(self):
        engine = RuleEngine()
        engine.load_rules_from_list(self.make_rules(2))
        rules = engine.get_rules()
        assert len(rules) == 2

    def test_detect_input_with_loaded_rules(self):
        engine = RuleEngine()
        rules = [
            RuleDefinition(
                id="I-01", name="Password Check", description="test",
                category="credential_leak", severity=Severity.P0, action="block",
                applicable_stages=["input"],
                detection=__import__("kasra.models.rule", fromlist=["DetectionConfig"]).DetectionConfig(
                    mode="any",
                    patterns=[
                        __import__("kasra.models.rule", fromlist=["PatternDefinition"]).PatternDefinition(
                            type="regex", value=r"password\s*[:=]\s*\w+", confidence=0.9,
                        )
                    ],
                ),
            )
        ]
        engine.load_rules_from_list(rules)
        result = engine.detect_input("my password=admin123")
        assert result.blocked

    def test_detect_input_no_match(self):
        engine = RuleEngine()
        engine.load_rules_from_list(self.make_rules())
        result = engine.detect_input("safe content")
        assert not result.blocked

    def test_get_rules_stage_filter(self):
        engine = RuleEngine()
        all_rules = [
            RuleDefinition(
                id="I-01", name="A", description="test",
                category="test", severity=Severity.P1, action="warn",
                applicable_stages=["input"],
            ),
            RuleDefinition(
                id="O-01", name="B", description="test",
                category="test", severity=Severity.P2, action="warn",
                applicable_stages=["output"],
            ),
        ]
        engine.load_rules_from_list(all_rules)
        input_rules = engine.get_rules_for_stage("input")
        assert len(input_rules) == 1


# ======================================================================
# Exceptions
# ======================================================================

class TestExceptions:
    def test_rule_load_error(self):
        e = RuleLoadError("Failed to load")
        assert "Failed to load" in str(e)
        assert isinstance(e, Exception)

    def test_rule_not_found_error(self):
        e = RuleNotFoundError("I-99 not found")
        assert "I-99" in str(e)
        assert isinstance(e, Exception)
