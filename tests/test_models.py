"""Unit tests for all model classes: enums, rule, result, context, events."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from datetime import datetime

from kasra.models.enums import Severity, ActionType, Stage, PatternType, MatchMode, PipelinePhase
from kasra.models.rule import (
    PatternDefinition, DetectionConfig, RuleConfig, RuleDefinition, RuleBundle,
)
from kasra.models.result import MatchSpan, MatchResult, DetectionResult, AggregatedResult
from kasra.models.context import RequestContext, SessionContext, FileContext
from kasra.models.events import AuditEvent


# ======================================================================
# Enums
# ======================================================================

class TestEnums:
    def test_severity_values(self):
        assert Severity.P0.value == "P0"
        assert Severity.P1.value == "P1"
        assert Severity.P2.value == "P2"

    def test_severity_ordering(self):
        assert list(Severity) == [Severity.P0, Severity.P1, Severity.P2]

    def test_action_type_values(self):
        assert ActionType.BLOCK.value == "block"
        assert ActionType.WARN.value == "warn"
        assert ActionType.REDACT.value == "redact"
        assert ActionType.CLEAN.value == "clean"
        assert ActionType.TRUNCATE.value == "truncate"
        assert ActionType.SOFT_ALLOW.value == "soft_allow"
        assert ActionType.DYNAMIC.value == "dynamic"

    def test_stage_values(self):
        assert Stage.INPUT.value == "input"
        assert Stage.OUTPUT.value == "output"
        assert Stage.BATCH.value == "batch"
        assert Stage.BEHAVIOR.value == "behavior"

    def test_pattern_type_values(self):
        assert PatternType.REGEX.value == "regex"
        assert PatternType.KEYWORD.value == "keyword"
        assert PatternType.ENTROPY.value == "entropy"
        assert PatternType.COMPOSITE.value == "composite"

    def test_match_mode_values(self):
        assert MatchMode.ANY.value == "any"
        assert MatchMode.ALL.value == "all"

    def test_pipeline_phase_values(self):
        assert PipelinePhase.PHASE1_FAST.value == "phase1_fast"
        assert PipelinePhase.PHASE2_BOUNDARY.value == "phase2_boundary"
        assert PipelinePhase.PHASE3_END_OF_STREAM.value == "phase3_eos"

    def test_enum_str_mixin(self):
        # str() on a StrEnum returns the value
        assert Severity.P0.value == "P0"
        assert ActionType.BLOCK.value == "block"


# ======================================================================
# PatternDefinition
# ======================================================================

class TestPatternDefinition:
    def test_minimal(self):
        p = PatternDefinition(type=PatternType.REGEX, value=r"\d+")
        assert p.confidence == 0.7
        assert p.sub_patterns is None

    def test_with_confidence(self):
        p = PatternDefinition(type=PatternType.KEYWORD, value="test", confidence=0.9)
        assert p.confidence == 0.9

    def test_entropy_fields(self):
        p = PatternDefinition(
            type=PatternType.ENTROPY, value="",
            confidence=4.5, min_length=20, min_entropy=3.0,
        )
        assert p.min_entropy == 3.0
        assert p.min_length == 20

    def test_sub_patterns(self):
        sub = PatternDefinition(type=PatternType.KEYWORD, value="child")
        p = PatternDefinition(
            type=PatternType.COMPOSITE, value="and",
            sub_patterns=[sub],
        )
        assert len(p.sub_patterns) == 1
        assert p.sub_patterns[0].value == "child"


# ======================================================================
# DetectionConfig
# ======================================================================

class TestDetectionConfig:
    def test_defaults(self):
        dc = DetectionConfig()
        assert dc.mode == MatchMode.ANY
        assert dc.patterns == []
        assert dc.max_matches == 10
        assert dc.min_length is None

    def test_with_patterns(self):
        patterns = [PatternDefinition(type=PatternType.REGEX, value=r"\d+")]
        dc = DetectionConfig(mode=MatchMode.ALL, patterns=patterns, max_matches=20)
        assert dc.mode == MatchMode.ALL
        assert len(dc.patterns) == 1
        assert dc.max_matches == 20

    def test_with_languages(self):
        dc = DetectionConfig(languages=["python", "javascript"])
        assert dc.languages == ["python", "javascript"]

    def test_min_length(self):
        dc = DetectionConfig(min_length=10)
        assert dc.min_length == 10


# ======================================================================
# RuleConfig
# ======================================================================

class TestRuleConfig:
    def test_defaults(self):
        rc = RuleConfig()
        assert rc.max_matches == 10
        assert rc.exclusions == []
        assert rc.redact_template is None
        assert rc.luhn_check is False
        assert rc.no_pattern_match is False

    def test_with_values(self):
        rc = RuleConfig(
            max_matches=50,
            redact_template="[REDACTED]",
            luhn_check=True,
            no_pattern_match=True,
            admin_alert=True,
            gdpr_audit=True,
            max_length=100000,
        )
        assert rc.max_matches == 50
        assert rc.redact_template == "[REDACTED]"
        assert rc.luhn_check is True
        assert rc.no_pattern_match is True
        assert rc.admin_alert is True
        assert rc.gdpr_audit is True
        assert rc.max_length == 100000

    def test_session_tracking(self):
        rc = RuleConfig(session_tracking=True, cumulative_score_threshold=5)
        assert rc.session_tracking is True
        assert rc.cumulative_score_threshold == 5

    def test_severity_reduction(self):
        rc = RuleConfig(
            modifier_rule=True,
            severity_reduction={"I-11": "P2", "I-12": "P2"},
        )
        assert rc.modifier_rule is True
        assert rc.severity_reduction["I-11"] == "P2"

    def test_context_boost(self):
        rc = RuleConfig(
            context_boost={"proximity_rules": ["I-12", "I-18"], "severity_override": "P1"},
        )
        assert rc.context_boost["severity_override"] == "P1"

    def test_link_to_rules(self):
        rc = RuleConfig(link_to_rules=["I-37"])
        assert rc.link_to_rules == ["I-37"]

    def test_flags(self):
        rc = RuleConfig(flags={"session_leak_marker": True})
        assert rc.flags["session_leak_marker"] is True


# ======================================================================
# RuleDefinition
# ======================================================================

class TestRuleDefinition:
    def make_rule(self, **kwargs):
        defaults = dict(
            id="I-01", name="Test Rule", description="A test rule",
            category="test", severity="P0", action="block",
        )
        defaults.update(kwargs)
        return RuleDefinition(**defaults)

    def test_minimal(self):
        rule = self.make_rule()
        assert rule.id == "I-01"
        assert rule.enabled is True
        assert rule.applicable_stages == ["input"]
        assert isinstance(rule.detection, DetectionConfig)
        assert isinstance(rule.config, RuleConfig)

    def test_with_detection(self):
        rule = self.make_rule(
            detection=DetectionConfig(
                patterns=[PatternDefinition(type=PatternType.REGEX, value=r"\d+")],
            ),
        )
        assert len(rule.detection.patterns) == 1

    def test_enabled_field(self):
        rule = self.make_rule(enabled=False)
        assert rule.enabled is False

    def test_applicable_stages(self):
        rule = self.make_rule(applicable_stages=["output", "batch"])
        assert "output" in rule.applicable_stages
        assert "batch" in rule.applicable_stages

    def test_p0_with_block(self):
        rule = self.make_rule(severity="P0", action="block")
        assert rule.severity == Severity.P0
        assert rule.action == ActionType.BLOCK

    def test_p0_with_warn(self):
        rule = self.make_rule(severity="P0", action="warn")
        assert rule.severity == Severity.P0
        assert rule.action == ActionType.WARN

    def test_p0_rejects_clean(self):
        with pytest.raises(ValidationError):
            self.make_rule(severity="P0", action="clean")

    def test_p2_rejects_block(self):
        with pytest.raises(ValidationError):
            self.make_rule(severity="P2", action="block")

    def test_rule_id_pattern_valid(self):
        for rid in ["I-01", "O-51", "SEC-03", "IAC-01", "ARCH-15"]:
            rule = self.make_rule(id=rid)
            assert rule.id == rid

    def test_rule_id_pattern_invalid(self):
        with pytest.raises(ValidationError):
            self.make_rule(id="invalid")

    def test_description_max_length(self):
        with pytest.raises(ValidationError):
            self.make_rule(description="x" * 2001)

    def test_custom_config(self):
        rule = self.make_rule(
            config=RuleConfig(max_matches=50, redact_template="[ID]"),
        )
        assert rule.config.max_matches == 50
        assert rule.config.redact_template == "[ID]"


# ======================================================================
# RuleBundle
# ======================================================================

class TestRuleBundle:
    def make_bundle(self, rules_count=1):
        rules = [
            RuleDefinition(
                id=f"I-{i:02d}", name=f"Rule {i}", description="test",
                category="test", severity="P0", action="block",
            )
            for i in range(1, rules_count + 1)
        ]
        return RuleBundle(bundle={"series": "I", "total": rules_count}, rules=rules)

    def test_minimal(self):
        b = self.make_bundle(1)
        assert b.bundle["series"] == "I"
        assert len(b.rules) == 1

    def test_multiple_rules(self):
        b = self.make_bundle(5)
        assert len(b.rules) == 5

    def test_empty_rules_raises(self):
        with pytest.raises(ValidationError):
            RuleBundle(bundle={"series": "I"}, rules=[])


# ======================================================================
# MatchSpan
# ======================================================================

class TestMatchSpan:
    def test_minimal(self):
        ms = MatchSpan(start=0, end=5, matched="hello")
        assert ms.start == 0
        assert ms.end == 5
        assert ms.matched == "hello"
        assert ms.redacted is None

    def test_with_redacted(self):
        ms = MatchSpan(start=0, end=5, matched="hello", redacted="[REDACTED]")
        assert ms.redacted == "[REDACTED]"

    def test_negative_start_raises(self):
        with pytest.raises(ValidationError):
            MatchSpan(start=-1, end=5, matched="x")

    def test_ordering(self):
        spans = [
            MatchSpan(start=10, end=15, matched="b"),
            MatchSpan(start=0, end=5, matched="a"),
        ]
        sorted_spans = sorted(spans, key=lambda s: s.start)
        assert sorted_spans[0].start == 0


# ======================================================================
# MatchResult
# ======================================================================

class TestMatchResult:
    def test_minimal(self):
        mr = MatchResult(rule_id="I-01", pattern_index=0, pattern_type="regex",
                         pattern_value="test", confidence=0.7)
        assert mr.rule_id == "I-01"
        assert mr.spans == []
        assert mr.matched_text is None

    def test_with_spans(self):
        mr = MatchResult(
            rule_id="I-01", pattern_index=0, pattern_type="regex",
            pattern_value="test", confidence=0.7,
            spans=[MatchSpan(start=0, end=4, matched="test")],
        )
        assert len(mr.spans) == 1

    def test_timestamp(self):
        mr = MatchResult(rule_id="I-01", pattern_index=0, pattern_type="regex",
                         pattern_value="test", confidence=0.7)
        assert mr.matched_at is not None
        assert hasattr(mr.matched_at, "tzinfo")


# ======================================================================
# DetectionResult
# ======================================================================

class TestDetectionResult:
    def test_minimal(self):
        dr = DetectionResult(
            rule_id="I-01", rule_name="Test", severity=Severity.P0,
            action=ActionType.BLOCK,
        )
        assert not dr.triggered
        assert dr.matches == []
        assert dr.error is None
        assert dr.evidence == []

    def test_triggered(self):
        dr = DetectionResult(
            rule_id="I-01", rule_name="Test", severity=Severity.P0,
            action=ActionType.BLOCK, triggered=True,
        )
        assert dr.triggered

    def test_match_count(self):
        dr = DetectionResult(
            rule_id="I-01", rule_name="Test", severity=Severity.P1,
            action=ActionType.WARN, triggered=True,
            matches=[
                MatchResult(rule_id="I-01", pattern_index=0, pattern_type="regex",
                            pattern_value="test", confidence=0.7,
                            spans=[MatchSpan(start=0, end=4, matched="test")]),
            ],
        )
        assert dr.match_count == 1


# ======================================================================
# AggregatedResult
# ======================================================================

class TestAggregatedResult:
    def test_defaults(self):
        ar = AggregatedResult()
        assert ar.overall_action == ActionType.WARN
        assert ar.overall_severity == Severity.P2
        assert ar.triggered_rules == []
        assert ar.blocked is False
        assert ar.truncated is False

    def test_add_result_triggered(self):
        ar = AggregatedResult()
        dr = DetectionResult(
            rule_id="I-01", rule_name="Test", severity=Severity.P0,
            action=ActionType.BLOCK, triggered=True,
        )
        ar.add_result(dr)
        assert len(ar.triggered_rules) == 1
        assert len(ar.all_results) == 1

    def test_add_result_not_triggered(self):
        ar = AggregatedResult()
        dr = DetectionResult(
            rule_id="I-01", rule_name="Test", severity=Severity.P0,
            action=ActionType.BLOCK, triggered=False,
        )
        ar.add_result(dr)
        assert len(ar.triggered_rules) == 0
        assert len(ar.all_results) == 1

    def test_p0_block_triggers_blocked(self):
        ar = AggregatedResult()
        dr = DetectionResult(
            rule_id="I-01", rule_name="Test", severity=Severity.P0,
            action=ActionType.BLOCK, triggered=True,
        )
        ar.add_result(dr)
        assert ar.blocked is True
        assert ar.overall_action == ActionType.BLOCK

    def test_p0_redact_triggers_blocked(self):
        ar = AggregatedResult()
        dr = DetectionResult(
            rule_id="I-01", rule_name="Test", severity=Severity.P0,
            action=ActionType.REDACT, triggered=True,
        )
        ar.add_result(dr)
        assert ar.blocked is True

    def test_p0_warn_does_not_block(self):
        ar = AggregatedResult()
        dr = DetectionResult(
            rule_id="O-01", rule_name="Test", severity=Severity.P0,
            action=ActionType.WARN, triggered=True,
        )
        ar.add_result(dr)
        assert ar.blocked is False  # P0+warn does not block

    def test_warning_accumulation(self):
        ar = AggregatedResult()
        dr = DetectionResult(
            rule_id="I-01", rule_name="Test", severity=Severity.P1,
            action=ActionType.WARN, triggered=True,
            matches=[
                MatchResult(rule_id="I-01", pattern_index=0, pattern_type="regex",
                            pattern_value="test", confidence=0.7,
                            matched_text="secret found"),
            ],
        )
        ar.add_result(dr)
        assert len(ar.warnings) == 1
        assert "secret found" in ar.warnings[0]

    def test_severity_escalation(self):
        ar = AggregatedResult()
        dr1 = DetectionResult(
            rule_id="I-01", rule_name="A", severity=Severity.P2,
            action=ActionType.WARN, triggered=True,
        )
        dr2 = DetectionResult(
            rule_id="I-02", rule_name="B", severity=Severity.P0,
            action=ActionType.WARN, triggered=True,
        )
        ar.add_result(dr1)
        assert ar.overall_severity == Severity.P2
        ar.add_result(dr2)
        assert ar.overall_severity == Severity.P0

    def test_serialization(self):
        ar = AggregatedResult(
            blocked=True,
            overall_action=ActionType.BLOCK,
            warnings=["test"],
        )
        d = ar.model_dump()
        assert d["blocked"] is True
        assert d["overall_action"] == "block"
        assert len(d["warnings"]) == 1


# ======================================================================
# RequestContext
# ======================================================================

class TestRequestContext:
    def test_defaults(self):
        ctx = RequestContext()
        assert ctx.source == "api"
        assert ctx.suspicion_score == 0
        assert ctx.content_length == 0
        assert ctx.headers == {}

    def test_with_values(self):
        ctx = RequestContext(
            request_id="req-1",
            content="test content",
            content_length=12,
            source="cli",
            user_id="user-1",
            ip_address="127.0.0.1",
            suspicion_score=5,
        )
        assert ctx.request_id == "req-1"
        assert ctx.content == "test content"
        assert ctx.content_length == 12
        assert ctx.source == "cli"
        assert ctx.suspicion_score == 5

    def test_timestamp_auto(self):
        ctx = RequestContext()
        assert ctx.timestamp is not None


# ======================================================================
# SessionContext
# ======================================================================

class TestSessionContext:
    def test_defaults(self):
        ctx = SessionContext()
        assert ctx.history_count == 0
        assert ctx.is_polluted is False
        assert ctx.suspicion_score == 0
        assert ctx.previous_results == []

    def test_with_values(self):
        ctx = SessionContext(
            session_id="sess-1",
            user_id="user-1",
            history_count=5,
            suspicion_score=20,
            is_polluted=True,
            previous_results=["I-01", "I-02"],
        )
        assert ctx.session_id == "sess-1"
        assert ctx.suspicion_score == 20
        assert ctx.is_polluted is True
        assert len(ctx.previous_results) == 2


# ======================================================================
# FileContext
# ======================================================================

class TestFileContext:
    def test_minimal(self):
        ctx = FileContext(file_path="test.py")
        assert ctx.file_path == "test.py"
        assert ctx.file_size == 0
        assert ctx.is_binary is False
        assert ctx.content == ""

    def test_with_values(self):
        ctx = FileContext(
            file_path="config.py", file_size=1024,
            mime_type="text/x-python", encoding="utf-8",
            language="python", content="print('hello')",
        )
        assert ctx.file_size == 1024
        assert ctx.mime_type == "text/x-python"
        assert ctx.language == "python"


# ======================================================================
# AuditEvent
# ======================================================================

class TestAuditEvent:
    def test_minimal(self):
        event = AuditEvent(
            event_id="evt-1",
            stage="input",
            rule_id="I-01",
            rule_name="Test",
            severity="P0",
            action="block",
        )
        assert event.event_id == "evt-1"
        assert event.gdpr_relevant is False

    def test_full(self):
        event = AuditEvent(
            event_id="evt-1", timestamp=datetime.utcnow(),
            stage="output", rule_id="O-01", rule_name="Dangerous",
            severity="P1", action="warn",
            user_id="u-1", session_id="s-1", request_id="r-1",
            source="api", content_snippet="eval(", content_length=20,
            match_count=1, gdpr_relevant=True,
        )
        assert event.user_id == "u-1"
        assert event.match_count == 1
        assert event.gdpr_relevant is True

    def test_serialization(self):
        event = AuditEvent(
            event_id="evt-1",
            stage="input", rule_id="I-01", rule_name="Test",
            severity="P0", action="block",
        )
        d = event.model_dump()
        assert d["rule_id"] == "I-01"
        assert d["stage"] == "input"
