"""Unit tests for all 7 action executors + ActionRegistry."""

from __future__ import annotations

import pytest

from kasra.actions.base import ActionExecutor, ActionRegistry, ActionResult
from kasra.actions.block import BlockAction
from kasra.actions.warn import WarnAction
from kasra.actions.redact import RedactAction
from kasra.actions.clean import CleanAction
from kasra.actions.truncate import TruncateAction
from kasra.actions.soft_allow import SoftAllowAction
from kasra.actions.dynamic import DynamicAction
from kasra.models.enums import ActionType
from kasra.models.result import AggregatedResult, MatchSpan


# ======================================================================
# ActionRegistry
# ======================================================================

class TestActionRegistry:
    def test_register_and_get(self):
        reg = ActionRegistry()
        reg.register(ActionType.BLOCK, BlockAction())
        executor = reg.get(ActionType.BLOCK)
        assert isinstance(executor, BlockAction)

    def test_get_missing_raises(self):
        reg = ActionRegistry()
        with pytest.raises(KeyError):
            reg.get(ActionType.WARN)

    def test_all_returns_copy(self):
        reg = ActionRegistry()
        reg.register(ActionType.BLOCK, BlockAction())
        reg.register(ActionType.WARN, WarnAction())
        all_ = reg.all()
        assert len(all_) == 2
        # Mutating the returned dict should not affect registry
        all_.clear()
        assert len(reg.all()) == 2

    def test_register_overwrite(self):
        reg = ActionRegistry()
        reg.register(ActionType.BLOCK, BlockAction())
        reg.register(ActionType.BLOCK, WarnAction())  # overwrite
        assert isinstance(reg.get(ActionType.BLOCK), WarnAction)


# ======================================================================
# ActionResult
# ======================================================================

class TestActionResult:
    def test_defaults(self):
        ar = ActionResult(action=ActionType.BLOCK)
        assert ar.blocked is False
        assert ar.content is None
        assert ar.warnings == []

    def test_full_construction(self):
        ar = ActionResult(
            action=ActionType.WARN,
            content="hello",
            blocked=False,
            warnings=["test warning"],
            truncated=False,
            redact_spans=[MatchSpan(start=0, end=5, matched="hello")],
        )
        assert ar.action == ActionType.WARN
        assert ar.content == "hello"
        assert "test warning" in ar.warnings
        assert len(ar.redact_spans) == 1

    def test_serialization(self):
        ar = ActionResult(action=ActionType.BLOCK, blocked=True)
        d = ar.model_dump()
        assert d["action"] == "block"
        assert d["blocked"] is True


# ======================================================================
# BlockAction
# ======================================================================

class TestBlockAction:
    def test_block(self):
        action = BlockAction()
        result = AggregatedResult(blocked=True, warnings=["blocked"])
        ar = action.apply("some content", result)
        assert ar.blocked
        assert ar.content is None
        assert ar.action == ActionType.BLOCK
        assert "blocked" in ar.warnings

    def test_block_no_warnings(self):
        action = BlockAction()
        result = AggregatedResult()
        ar = action.apply("content", result)
        assert ar.blocked
        assert ar.content is None


# ======================================================================
# WarnAction
# ======================================================================

class TestWarnAction:
    def test_warn_preserves_content(self):
        action = WarnAction()
        result = AggregatedResult(warnings=["careful!"])
        ar = action.apply("original content", result)
        assert not ar.blocked
        assert ar.content == "original content"
        assert "careful!" in ar.warnings

    def test_warn_no_warnings(self):
        action = WarnAction()
        result = AggregatedResult()
        ar = action.apply("content", result)
        assert not ar.blocked
        assert ar.content == "content"
        assert ar.warnings == []


# ======================================================================
# RedactAction
# ======================================================================

class TestRedactAction:
    def test_redact_single_span(self):
        action = RedactAction()
        result = AggregatedResult(
            redact_spans=[MatchSpan(start=3, end=9, matched="secret")],
        )
        ar = action.apply("my secret password", result)
        assert "[REDACTED]" in ar.content
        assert "secret" not in ar.content
        assert not ar.blocked

    def test_redact_multiple_spans(self):
        action = RedactAction()
        result = AggregatedResult(
            redact_spans=[
                MatchSpan(start=3, end=9, matched="secret"),
                MatchSpan(start=17, end=25, matched="password"),
            ],
        )
        ar = action.apply("my secret my password", result)
        assert "[REDACTED]" in ar.content
        assert "secret" not in ar.content
        assert "password" not in ar.content

    def test_redact_reverse_order_correctness(self):
        """Redaction applies spans in reverse order so positions stay valid."""
        action = RedactAction()
        result = AggregatedResult(
            redact_spans=[
                MatchSpan(start=0, end=2, matched="my"),
                MatchSpan(start=3, end=9, matched="secret"),
            ],
        )
        ar = action.apply("my secret", result)
        assert "[REDACTED]" in ar.content
        assert ar.content.count("[REDACTED]") == 2

    def test_custom_redact_template(self):
        action = RedactAction()
        result = AggregatedResult(
            redact_spans=[MatchSpan(start=0, end=5, matched="hello", redacted="[CUSTOM]")],
        )
        ar = action.apply("hello world", result)
        assert "[CUSTOM]" in ar.content
        assert "hello" not in ar.content

    def test_no_spans_no_change(self):
        action = RedactAction()
        result = AggregatedResult()
        ar = action.apply("hello world", result)
        assert ar.content == "hello world"

    def test_empty_content(self):
        action = RedactAction()
        result = AggregatedResult(redact_spans=[])
        ar = action.apply("", result)
        assert ar.content == ""


# ======================================================================
# CleanAction
# ======================================================================

class TestCleanAction:
    def test_clean_removes_invisible_chars(self):
        action = CleanAction()
        dirty = "hello​world"  # contains zero-width space
        result = AggregatedResult()
        ar = action.apply(dirty, result)
        assert "​" not in ar.content
        assert "helloworld" in ar.content.replace(" ", "")

    def test_clean_normalizes_nfkc(self):
        action = CleanAction()
        # Fullwidth letters should be normalized to ASCII
        dirty = "ＨＥＬＬＯ"
        result = AggregatedResult()
        ar = action.apply(dirty, result)
        assert ar.content == "HELLO"

    def test_clean_preserves_normal_text(self):
        action = CleanAction()
        result = AggregatedResult()
        ar = action.apply("hello world", result)
        assert ar.content == "hello world"
        assert not ar.blocked

    def test_clean_removes_control_chars(self):
        action = CleanAction()
        dirty = "hello\x00world\x1f"
        result = AggregatedResult()
        ar = action.apply(dirty, result)
        assert "hello" in ar.content
        assert "world" in ar.content
        assert "\x00" not in ar.content

    def test_clean_preserves_newlines(self):
        action = CleanAction()
        dirty = "line1\nline2\nline3"
        result = AggregatedResult()
        ar = action.apply(dirty, result)
        assert ar.content.count("\n") == 2


# ======================================================================
# TruncateAction
# ======================================================================

class TestTruncateAction:
    def test_truncate_long_content(self):
        action = TruncateAction(max_length=50)
        result = AggregatedResult()
        ar = action.apply("A" * 100, result)
        assert ar.truncated
        assert len(ar.content) < 100
        assert "<<TRUNCATED>>" in ar.content

    def test_truncate_short_content_no_change(self):
        action = TruncateAction(max_length=100)
        result = AggregatedResult()
        ar = action.apply("hello", result)
        assert not ar.truncated
        assert ar.content == "hello"

    def test_truncate_empty_content(self):
        action = TruncateAction(max_length=100)
        result = AggregatedResult()
        ar = action.apply("", result)
        assert not ar.truncated

    def test_truncate_default_max_length(self):
        action = TruncateAction()
        result = AggregatedResult()
        ar = action.apply("A" * 5001, result)
        assert ar.truncated
        assert len(ar.content) < 5001

    def test_truncate_boundary_lookback(self):
        """Truncate at newline boundary when possible."""
        action = TruncateAction(max_length=20)
        result = AggregatedResult()
        content = "line one\nline two\nline three"
        ar = action.apply(content, result)
        assert ar.truncated
        assert ar.content.rstrip().endswith("<<TRUNCATED>>")


# ======================================================================
# SoftAllowAction
# ======================================================================

class TestSoftAllowAction:
    def test_soft_allow_passthrough(self):
        action = SoftAllowAction()
        result = AggregatedResult(warnings=["advisory"])
        ar = action.apply("content", result)
        assert not ar.blocked
        assert ar.content == "content"
        assert "advisory" in ar.warnings

    def test_soft_allow_no_warnings(self):
        action = SoftAllowAction()
        result = AggregatedResult()
        ar = action.apply("content", result)
        assert not ar.blocked
        assert ar.content == "content"


# ======================================================================
# DynamicAction
# ======================================================================

class TestDynamicAction:
    def test_dynamic_no_trigger(self):
        action = DynamicAction()
        result = AggregatedResult()
        ar = action.apply("normal content", result)
        assert not ar.blocked
        assert ar.content == "normal content"

    def test_dynamic_with_trigger(self):
        action = DynamicAction()
        result = AggregatedResult(blocked=True)
        ar = action.apply("dangerous", result)
        # Dynamic passes through the aggregated result
        assert ar is not None


# ======================================================================
# ActionExecutor ABC
# ======================================================================

class TestActionExecutorABC:
    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            ActionExecutor()  # abstract

    def test_action_type_attribute(self):
        assert BlockAction.action_type == ActionType.BLOCK
        assert WarnAction.action_type == ActionType.WARN
        assert RedactAction.action_type == ActionType.REDACT
        assert CleanAction.action_type == ActionType.CLEAN
        assert TruncateAction.action_type == ActionType.TRUNCATE
        assert SoftAllowAction.action_type == ActionType.SOFT_ALLOW
        assert DynamicAction.action_type == ActionType.DYNAMIC
