"""Unit tests for rules/loader, rules/store, core/registry, exceptions."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from kasra.rules.loader import RuleLoader
from kasra.rules.store import RuleStore
from kasra.core.registry import RuleRegistry
from kasra.exceptions.errors import RuleLoadError, RuleNotFoundError
from kasra.models.enums import Severity
from kasra.models.rule import RuleDefinition


# ======================================================================
# RuleLoader
# ======================================================================

class TestRuleLoader:
    SAMPLE_BUNDLE = json.dumps({
        "bundle": {"series": "I", "name": "Test", "version": "1.0", "total": 2},
        "rules": [
            {"id": "I-01", "name": "Rule 1", "description": "First rule",
             "category": "test", "severity": "P0", "action": "block"},
            {"id": "I-02", "name": "Rule 2", "description": "Second rule",
             "category": "test", "severity": "P1", "action": "warn"},
        ],
    })

    @pytest.fixture
    def tmp_dir(self):
        with tempfile.TemporaryDirectory() as d:
            yield Path(d)

    def test_load_json_from_string(self):
        loader = RuleLoader()
        rules = loader.load_json(self.SAMPLE_BUNDLE)
        assert len(rules) == 2
        assert rules[0].id == "I-01"
        assert rules[1].id == "I-02"

    def test_load_json_invalid(self):
        loader = RuleLoader()
        with pytest.raises(RuleLoadError):
            loader.load_json("not json", source="test")

    def test_load_file(self, tmp_dir):
        f = tmp_dir / "test-rules.json"
        f.write_text(self.SAMPLE_BUNDLE)
        loader = RuleLoader(rules_dir=str(tmp_dir))
        rules = loader.load_file(str(f))
        assert len(rules) == 2

    def test_load_file_not_found(self):
        loader = RuleLoader()
        with pytest.raises(RuleLoadError):
            loader.load_file("/nonexistent/path.json")

    def test_load_all(self, tmp_dir):
        f = tmp_dir / "test-rules.json"
        f.write_text(self.SAMPLE_BUNDLE)
        loader = RuleLoader(rules_dir=str(tmp_dir))
        rules = loader.load_all()
        assert len(rules) == 2

    def test_load_all_empty_dir(self, tmp_dir):
        loader = RuleLoader(rules_dir=str(tmp_dir))
        rules = loader.load_all()
        assert rules == []

    def test_load_all_skips_hidden(self, tmp_dir):
        f1 = tmp_dir / "test-rules.json"
        f1.write_text(self.SAMPLE_BUNDLE)
        f2 = tmp_dir / "_hidden.json"
        f2.write_text(self.SAMPLE_BUNDLE)
        f3 = tmp_dir / ".dotfile.json"
        f3.write_text(self.SAMPLE_BUNDLE)
        loader = RuleLoader(rules_dir=str(tmp_dir))
        rules = loader.load_all()
        assert len(rules) == 2  # Only test-rules loaded

    def test_load_all_with_errors(self, tmp_dir):
        f1 = tmp_dir / "good.json"
        f1.write_text(self.SAMPLE_BUNDLE)
        f2 = tmp_dir / "bad.json"
        f2.write_text("not json")
        loader = RuleLoader(rules_dir=str(tmp_dir))
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            rules = loader.load_all()
            assert len(rules) == 2  # Good file still loads
            assert len(w) >= 1  # Warning about bad file

    def test_load_file_with_bundle_validation_error(self, tmp_dir):
        f = tmp_dir / "bad.json"
        f.write_text(json.dumps({
            "bundle": {"series": "I"},
            # Missing rules field
        }))
        loader = RuleLoader(rules_dir=str(tmp_dir))
        with pytest.raises(RuleLoadError):
            loader.load_file(str(f))

    def test_rules_dir_property(self, tmp_dir):
        loader = RuleLoader(rules_dir=str(tmp_dir))
        assert loader.rules_dir == tmp_dir.resolve()

    def test_default_rules_dir_exists(self):
        """When no rules_dir given, auto-detects from package."""
        loader = RuleLoader()
        assert loader.rules_dir is not None
        assert isinstance(loader.rules_dir, Path)


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
        # count_by_severity returns dict for all severity levels
        counts = store.count_by_severity()
        # Should have all severity keys
        assert len(counts) == 3
        # P0 should have at least 1
        assert counts[Severity.P0] >= 1

    def test_atomic_replace(self):
        """bulk_replace is atomic — new dict swapped in after full construction."""
        store = RuleStore()
        store.bulk_replace(self.make_rules(3))
        # Snapshot before mutation
        snapshot = store.all()
        # During bulk_replace, readers should see consistent state
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
        # P0 first, then P1
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
        # Add new rule to store directly
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
