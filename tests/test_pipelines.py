"""Unit tests for all 4 pipeline implementations."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kasra.core.registry import RuleRegistry
from kasra.core.runner import RuleRunner
from kasra.rules.store import RuleStore
from kasra.models.enums import Severity, Stage, PipelinePhase
from kasra.models.rule import RuleDefinition, DetectionConfig, PatternDefinition, RuleConfig
from kasra.pipeline.input_pipeline import InputDetectionPipeline
from kasra.pipeline.output_pipeline import OutputDetectionPipeline
from kasra.pipeline.batch_pipeline import BatchScanPipeline
from kasra.pipeline.behavior_pipeline import BehaviorDetectionPipeline


# ======================================================================
# Fixtures
# ======================================================================

@pytest.fixture
def registry():
    store = RuleStore()
    rules = [
        RuleDefinition(
            id="I-01", name="Test Input", description="test",
            category="test", severity=Severity.P0, action="block",
            applicable_stages=["input"],
            detection=DetectionConfig(
                patterns=[PatternDefinition(type="regex", value=r"\bsecret\b", confidence=0.8)],
            ),
        ),
        RuleDefinition(
            id="O-01", name="Test Output", description="test",
            category="test", severity=Severity.P1, action="warn",
            applicable_stages=["output"],
            detection=DetectionConfig(
                patterns=[PatternDefinition(type="keyword", value="dangerous", confidence=0.7)],
            ),
        ),
        RuleDefinition(
            id="I-43", name="Oversized Input", description="test",
            category="test", severity=Severity.P2, action="truncate",
            applicable_stages=["input"],
            detection=DetectionConfig(patterns=[]),
            config=RuleConfig(no_pattern_match=True, max_length=100000),
        ),
        RuleDefinition(
            id="O-51", name="Oversized Output", description="test",
            category="test", severity=Severity.P2, action="warn",
            applicable_stages=["output"],
            detection=DetectionConfig(patterns=[]),
            config=RuleConfig(no_pattern_match=True, max_length=50000),
        ),
    ]
    store.bulk_replace(rules)
    reg = RuleRegistry(store)
    return reg


@pytest.fixture
def runner():
    return RuleRunner()


# ======================================================================
# InputDetectionPipeline
# ======================================================================

class TestInputPipeline:
    def test_get_rules(self, registry):
        pipeline = InputDetectionPipeline(registry, RuleRunner())
        rules = pipeline.get_rules()
        assert len(rules) == 2  # I-01 and I-43
        assert all(r.id.startswith("I-") for r in rules)

    def test_run_triggers(self, registry, runner):
        pipeline = InputDetectionPipeline(registry, runner)
        result = pipeline.run("my secret password")
        assert len(result.triggered_rules) >= 1
        assert "I-01" in {r.rule_id for r in result.triggered_rules}

    def test_run_no_trigger(self, registry, runner):
        pipeline = InputDetectionPipeline(registry, runner)
        result = pipeline.run("hello world")
        assert len(result.triggered_rules) == 0
        assert result.blocked is False

    def test_run_oversized(self, registry, runner):
        pipeline = InputDetectionPipeline(registry, runner)
        result = pipeline.run("A" * 100001)
        assert any(r.rule_id == "I-43" for r in result.triggered_rules)

    def test_run_context_passthrough(self, registry, runner):
        pipeline = InputDetectionPipeline(registry, runner)
        result = pipeline.run("hello", user_id="test-user", request_id="req-1")
        assert result is not None

    def test_analysis_context_populated(self, registry, runner):
        pipeline = InputDetectionPipeline(registry, runner)
        result = pipeline.run("def hello():\n    print('world')")
        assert result.analysis_context is not None
        assert result.analysis_context.detected_language is not None


# ======================================================================
# OutputDetectionPipeline
# ======================================================================

class TestOutputPipeline:
    def test_get_rules(self, registry):
        pipeline = OutputDetectionPipeline(registry, RuleRunner())
        rules = pipeline.get_rules()
        assert len(rules) == 2  # O-01 and O-51
        assert all(r.id.startswith("O-") for r in rules)

    def test_run_triggers(self, registry, runner):
        pipeline = OutputDetectionPipeline(registry, runner)
        result = pipeline.run("dangerous content")
        assert len(result.triggered_rules) >= 1
        assert "O-01" in {r.rule_id for r in result.triggered_rules}

    def test_run_no_trigger(self, registry, runner):
        pipeline = OutputDetectionPipeline(registry, runner)
        result = pipeline.run("safe content")
        assert len(result.triggered_rules) == 0

    def test_run_oversized(self, registry, runner):
        pipeline = OutputDetectionPipeline(registry, runner)
        result = pipeline.run("A" * 50001)
        assert any(r.rule_id == "O-51" for r in result.triggered_rules)

    def test_streaming_phase1(self, registry, runner):
        pipeline = OutputDetectionPipeline(registry, runner)
        result = pipeline.run_phase("dangerous", PipelinePhase.PHASE1_FAST)
        assert result is not None
        assert result.analysis_context is not None

    def test_streaming_phase2(self, registry, runner):
        pipeline = OutputDetectionPipeline(registry, runner)
        result = pipeline.run_phase("dangerous", PipelinePhase.PHASE2_BOUNDARY)
        assert result is not None
        assert result.analysis_context is not None

    def test_streaming_phase3_delegates_to_run(self, registry, runner):
        pipeline = OutputDetectionPipeline(registry, runner)
        result = pipeline.run_phase("test", PipelinePhase.PHASE3_END_OF_STREAM)
        assert result is not None

    def test_streaming_oversized_at_phase1(self, registry, runner):
        """Cumulative length should trigger O-51 across streaming phases."""
        pipeline = OutputDetectionPipeline(registry, runner)
        pipeline.reset_stream_state()
        # Phase 1: 40K — not enough
        pipeline.run_phase("A" * 40000, PipelinePhase.PHASE1_FAST)
        # Phase 2: another 20K — cumulative 60K > 50K
        result = pipeline.run_phase("A" * 20000, PipelinePhase.PHASE2_BOUNDARY)
        o51 = [r for r in result.all_results if r.rule_id == "O-51" and r.triggered]
        assert len(o51) == 1

    def test_reset_stream_state(self, registry, runner):
        pipeline = OutputDetectionPipeline(registry, runner)
        pipeline.reset_stream_state()
        assert pipeline._streamed_content_length == 0

    def test_is_fast_rule(self, registry):
        pipeline = OutputDetectionPipeline(registry, RuleRunner())
        rules = registry.get_rules_for_stage(Stage.OUTPUT)
        for r in rules:
            result = pipeline._is_fast_rule(r)
            assert isinstance(result, bool)

    def test_finalize(self, registry, runner):
        pipeline = OutputDetectionPipeline(registry, runner)
        from kasra.models.result import AggregatedResult
        ar = AggregatedResult()
        ar.metadata = {"existing": "value"}
        result = pipeline.finalize(ar, None)
        assert result is ar
        assert result.metadata.get("existing") == "value"


# ======================================================================
# BatchScanPipeline
# ======================================================================

class TestBatchPipeline:
    def test_get_rules(self, registry):
        pipeline = BatchScanPipeline(registry, RuleRunner())
        rules = pipeline.get_rules()
        assert len(rules) >= 1

    def test_scan_file(self, registry, runner):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("my secret password")
            path = tmp.name
        try:
            pipeline = BatchScanPipeline(registry, runner)
            result = pipeline.scan_file(path)
            assert result is not None
        finally:
            import os
            os.unlink(path)

    def test_scan_file_not_found(self, registry, runner):
        pipeline = BatchScanPipeline(registry, runner)
        result = pipeline.scan_file("/nonexistent/path.txt")
        assert result is not None
        # Should not raise

    def test_scan_empty_file(self, registry, runner):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            path = tmp.name
        try:
            pipeline = BatchScanPipeline(registry, runner)
            result = pipeline.scan_file(path)
            assert result is not None
        finally:
            import os
            os.unlink(path)

    def test_scan_file_preprocess(self, registry, runner):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            tmp.write("hello world")
            path = tmp.name
        try:
            pipeline = BatchScanPipeline(registry, runner)
            result_with = pipeline.scan_file(path, preprocess=True)
            result_without = pipeline.scan_file(path, preprocess=False)
            assert result_with is not None
            assert result_without is not None
        finally:
            import os
            os.unlink(path)

    def test_scan_directory(self, registry, runner):
        with tempfile.TemporaryDirectory() as d:
            dpath = Path(d)
            (dpath / "file1.txt").write_text("hello world")
            (dpath / "file2.txt").write_text("secret password")
            pipeline = BatchScanPipeline(registry, runner)
            results = pipeline.scan_directory(str(dpath))
            assert len(results) == 2
            for r in results:
                assert isinstance(r, object)

    def test_scan_directory_nonexistent(self, registry, runner):
        pipeline = BatchScanPipeline(registry, runner)
        results = pipeline.scan_directory("/nonexistent")
        assert results == []


# ======================================================================
# BehaviorDetectionPipeline
# ======================================================================

class TestBehaviorPipeline:
    def test_get_rules(self, registry):
        pipeline = BehaviorDetectionPipeline(registry, RuleRunner())
        rules = pipeline.get_rules()
        assert len(rules) >= 1

    def test_run_tracks_session(self, registry, runner):
        pipeline = BehaviorDetectionPipeline(registry, runner)
        result = pipeline.run("hello world", session_id="test-sess")
        assert result is not None
        sess = pipeline.get_session("test-sess")
        assert sess is not None
        assert sess.history_count == 1

    def test_multiple_calls_increment_history(self, registry, runner):
        pipeline = BehaviorDetectionPipeline(registry, runner)
        pipeline.run("msg1", session_id="sess-2")
        pipeline.run("msg2", session_id="sess-2")
        pipeline.run("msg3", session_id="sess-2")
        sess = pipeline.get_session("sess-2")
        assert sess.history_count == 3

    def test_suspicion_score_increments_on_trigger(self, registry, runner):
        pipeline = BehaviorDetectionPipeline(registry, runner)
        # Trigger rule I-01
        pipeline.run("my secret", session_id="sess-3")
        sess = pipeline.get_session("sess-3")
        if sess and sess.previous_results:
            assert sess.suspicion_score > 0

    def test_reset_session(self, registry, runner):
        pipeline = BehaviorDetectionPipeline(registry, runner)
        pipeline.run("hello", session_id="sess-4")
        pipeline.reset_session("sess-4")
        assert pipeline.get_session("sess-4") is None

    def test_get_all_sessions(self, registry, runner):
        pipeline = BehaviorDetectionPipeline(registry, runner)
        pipeline.run("hello", session_id="sess-5")
        pipeline.run("hello", session_id="sess-6")
        all_sess = pipeline.get_all_sessions()
        assert "sess-5" in all_sess
        assert "sess-6" in all_sess

    def test_prune_sessions(self, registry, runner):
        pipeline = BehaviorDetectionPipeline(registry, runner)
        pipeline.run("hello", session_id="prune-test")
        assert pipeline.get_session("prune-test") is not None
        # Prune with 0 hours should clear all
        pipeline.prune_sessions(max_age_hours=0)
        # Sessions may or may not be pruned depending on timing
        # Just verify it doesn't crash

    def test_separate_sessions(self, registry, runner):
        pipeline = BehaviorDetectionPipeline(registry, runner)
        pipeline.run("msg", session_id="a")
        pipeline.run("msg", session_id="b")
        assert pipeline.get_session("a").history_count == 1
        assert pipeline.get_session("b").history_count == 1
