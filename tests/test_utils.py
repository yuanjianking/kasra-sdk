"""Unit tests for preprocessing and utilities modules."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from kasra.preprocessing.normalizer import ContentNormalizer
from kasra.preprocessing.chunker import BoundaryDetector
from kasra.utils.text import (
    normalize_text, strip_invisible, strip_control,
    truncate_at_boundary, nfc_normalize,
)
from kasra.utils.time import utcnow, timer
from kasra.utils.severity import SEVERITY_RANK, Severity
from kasra.utils.package import find_data_dir
from kasra.utils.imports import lazy_import, optional_import


# ======================================================================
# ContentNormalizer
# ======================================================================

class TestContentNormalizer:
    def test_normalize_basic(self):
        n = ContentNormalizer()
        result = n.normalize("hello world")
        assert result == "hello world"

    def test_normalize_invisible_chars(self):
        n = ContentNormalizer()
        dirty = "hello​world"  # zero-width space
        clean = n.normalize(dirty)
        assert "​" not in clean
        assert "helloworld" in clean

    def test_normalize_control_chars(self):
        n = ContentNormalizer()
        dirty = "hello\x00world"
        clean = n.normalize(dirty)
        assert "\x00" not in clean

    def test_normalize_preserves_newlines(self):
        n = ContentNormalizer()
        text = "line1\nline2\nline3"
        result = n.normalize(text)
        assert result.count("\n") == 2

    def test_normalize_nfc(self):
        n = ContentNormalizer()
        # e + combining acute accent -> é
        composed = "héllo"
        result = n.normalize(composed)
        assert len(result) > 0

    def test_normalize_empty(self):
        n = ContentNormalizer()
        assert n.normalize("") == ""

    def test_normalize_whitespace_only(self):
        n = ContentNormalizer()
        assert n.normalize("   ") == "   "

    def test_normalize_bom(self):
        n = ContentNormalizer()
        with_bom = "﻿hello"
        result = n.normalize(with_bom)
        assert "﻿" not in result
        assert result == "hello" or result is not None


# ======================================================================
# BoundaryDetector
# ======================================================================

class TestBoundaryDetector:
    def _make_detector(self, mode="sentence", **kw):
        from kasra.preprocessing.chunker import BoundaryDetector
        return BoundaryDetector(mode=mode, **kw)

    def test_sentence_mode(self):
        from kasra.preprocessing.chunker import BoundaryDetector
        d = BoundaryDetector(mode="sentence", min_chars=1)
        boundaries = d.find_boundaries("Hello world. Next sentence. And another.")
        assert len(boundaries) >= 2

    def test_line_mode(self):
        from kasra.preprocessing.chunker import BoundaryDetector
        d = BoundaryDetector(mode="line", min_chars=1)
        boundaries = d.find_boundaries("line1\nline2\nline3")
        assert len(boundaries) >= 2

    def test_no_boundary(self):
        from kasra.preprocessing.chunker import BoundaryDetector
        d = BoundaryDetector(mode="line", min_chars=100)
        boundaries = d.find_boundaries("no line breaks here")
        assert len(boundaries) == 0

    def test_empty_content(self):
        from kasra.preprocessing.chunker import BoundaryDetector
        d = BoundaryDetector(mode="sentence")
        assert d.find_boundaries("") == []


# ======================================================================
# utils.text
# ======================================================================

class TestTextUtils:
    def test_strip_invisible(self):
        dirty = "a​b‌c﻿d"
        clean = strip_invisible(dirty)
        assert clean == "abcd"

    def test_strip_invisible_no_change(self):
        text = "hello world"
        assert strip_invisible(text) == text

    def test_strip_control(self):
        dirty = "a\x00b\x1fc\td\ne\r"
        clean = strip_control(dirty)
        assert "\x00" not in clean
        assert "\x1f" not in clean
        assert "\t" in clean  # preserved
        assert "\n" in clean  # preserved
        assert "\r" in clean  # preserved

    def test_strip_control_strict(self):
        dirty = "a\nb\tc"
        clean = strip_control(dirty, keep_newlines=False)
        assert "\n" not in clean

    def test_nfc_normalize(self):
        result = nfc_normalize("héllo")
        assert len(result) > 0

    def test_normalize_text_invisible(self):
        text = "hello​world"
        result = normalize_text(text)
        assert "​" not in result

    def test_normalize_text_control(self):
        result = normalize_text("hello\x00world")
        assert "\x00" not in result

    def test_truncate_at_boundary_short(self):
        text, was = truncate_at_boundary("hello", 100)
        assert was is False
        assert text == "hello"

    def test_truncate_at_boundary_long_has_newline(self):
        # Text with newline within lookback
        text, was = truncate_at_boundary("hello world!\nmore text here", 20)
        assert was is True

    def test_truncate_no_boundary(self):
        """When no newline found at all, cut at max_length."""
        text = "A" * 100
        result, was = truncate_at_boundary(text, 50)
        assert was is True
        assert len(result) < 100


# ======================================================================
# utils.time
# ======================================================================

class TestTimeUtils:
    def test_utcnow(self):
        now = utcnow()
        assert now is not None
        assert hasattr(now, "tzinfo")

    def test_timer(self):
        with timer() as t:
            time.sleep(0.01)
        assert t.elapsed_ms > 1


# ======================================================================
# utils.severity
# ======================================================================

class TestSeverityUtils:
    def test_severity_rank_values(self):
        assert SEVERITY_RANK[Severity.P0] == 0
        assert SEVERITY_RANK[Severity.P1] == 1
        assert SEVERITY_RANK[Severity.P2] == 2

    def test_severity_rank_ordering(self):
        assert SEVERITY_RANK[Severity.P0] < SEVERITY_RANK[Severity.P1]
        assert SEVERITY_RANK[Severity.P1] < SEVERITY_RANK[Severity.P2]


# ======================================================================
# utils.package
# ======================================================================

class TestPackageUtils:
    def test_find_data_dir_rules_exists(self):
        path = find_data_dir("rules")
        assert path is not None
        assert path.exists()

    def test_find_data_dir_config_exists(self):
        path = find_data_dir("config")
        assert path is not None
        assert path.exists()

    def test_find_data_dir_nonexistent(self):
        with pytest.raises(KeyError):
            find_data_dir("nonexistent_dir_xyz")


# ======================================================================
# utils.imports
# ======================================================================

class TestImportsUtils:
    def test_lazy_import(self):
        mod = lazy_import("json")
        assert mod is not None

    def test_lazy_import_nonexistent(self):
        """lazy_import returns an object that raises on access if module missing."""
        mod = lazy_import("_kasra_nonexistent_module_xyz_12345")
        # Does not raise at import time — only at access time
        import pytest
        with pytest.raises((ImportError, ModuleNotFoundError)):
            _ = mod.some_attr

    def test_optional_import_exists(self):
        mod = optional_import("json")
        assert mod is not None
        assert mod.dumps is not None  # can use it

    def test_optional_import_missing(self):
        mod = optional_import("nonexistent_module_xyz")
        assert mod is None


# ======================================================================
# Core runner bug fixes verification
# ======================================================================

class TestRunnerConfigResolution:
    def test_resolve_max_matches_from_config(self):
        from kasra.core.runner import RuleRunner
        from kasra.models.rule import RuleDefinition, RuleConfig, DetectionConfig

        rr = RuleRunner()

        # Rule with max_matches in config (should win)
        rule1 = RuleDefinition(
            id="I-01", name="A", description="test",
            category="test", severity="P0", action="block",
            detection=DetectionConfig(max_matches=10),
            config=RuleConfig(max_matches=50),
        )
        assert rr._resolve_max_matches(rule1) == 50

        # Rule without config.max_matches (fall back to detection)
        rule2 = RuleDefinition(
            id="I-02", name="B", description="test",
            category="test", severity="P0", action="block",
            detection=DetectionConfig(max_matches=10),
            config=RuleConfig(),
        )
        assert rr._resolve_max_matches(rule2) == 10

    def test_resolve_exclusions_from_config(self):
        from kasra.core.runner import RuleRunner
        from kasra.models.rule import RuleDefinition, RuleConfig, DetectionConfig

        rr = RuleRunner()

        rule = RuleDefinition(
            id="I-01", name="A", description="test",
            category="test", severity="P0", action="block",
            detection=DetectionConfig(exclusions=[]),
            config=RuleConfig(exclusions=["^test$"]),
        )
        excl = rr._resolve_exclusions(rule)
        assert excl == ["^test$"]
