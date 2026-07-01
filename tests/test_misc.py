"""Unit tests for config, hooks, and context/buffer."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest
import yaml

from kasra.config.global_config import GlobalConfig
from kasra.config.loader import ConfigLoader
from kasra.context.buffer import ChunkBuffer
from kasra.hooks.base import Hook
from kasra.hooks.registry import HookRegistry
from kasra.hooks.builtin import MetricsCollector
from kasra.models.result import AggregatedResult, DetectionResult
from kasra.models.enums import Severity, ActionType
from kasra.models.context import RequestContext


# ======================================================================
# GlobalConfig
# ======================================================================

class TestGlobalConfig:
    def test_defaults(self):
        cfg = GlobalConfig()
        assert cfg.engine.max_concurrent_rules == 20
        assert cfg.pipeline.input.enabled is True
        assert cfg.audit.enabled is True
        assert cfg.audit.log_to_console is True
        assert cfg.audit.jsonl_path == "kasra-audit.jsonl"

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("KASRA_ENGINE__MAX_CONCURRENT_RULES", "50")
        cfg = GlobalConfig()
        assert cfg.engine.max_concurrent_rules == 50

    def test_env_override_audit(self, monkeypatch):
        monkeypatch.setenv("KASRA_AUDIT__ENABLED", "false")
        cfg = GlobalConfig()
        assert cfg.audit.enabled is False

    def test_env_override_bool_true(self, monkeypatch):
        monkeypatch.setenv("KASRA_AUDIT__LOG_TO_CONSOLE", "true")
        cfg = GlobalConfig()
        assert cfg.audit.log_to_console is True


# ======================================================================
# ConfigLoader
# ======================================================================

class TestConfigLoader:
    def test_default_loader(self):
        loader = ConfigLoader()
        cfg = loader.load()
        assert cfg is not None
        assert isinstance(cfg, GlobalConfig)

    def test_load_from_yaml(self):
        with tempfile.TemporaryDirectory() as d:
            dpath = Path(d)
            (dpath / "default.yaml").write_text(yaml.dump({
                "engine": {"max_concurrent_rules": 30},
                "audit": {"enabled": False},
            }))
            loader = ConfigLoader(config_dir=str(dpath))
            cfg = loader.load()
            assert cfg.engine.max_concurrent_rules == 30
            assert cfg.audit.enabled is False

    def test_override_yaml_precedence(self):
        with tempfile.TemporaryDirectory() as d:
            dpath = Path(d)
            (dpath / "default.yaml").write_text(yaml.dump({
                "engine": {"max_concurrent_rules": 20, "cache_compiled_patterns": True},
            }))
            (dpath / "override.yaml").write_text(yaml.dump({
                "engine": {"max_concurrent_rules": 50},
            }))
            loader = ConfigLoader(config_dir=str(dpath))
            cfg = loader.load()
            # override takes precedence over default
            assert cfg.engine.max_concurrent_rules == 50

    def test_nonexistent_dir(self):
        loader = ConfigLoader(config_dir="/nonexistent/path")
        cfg = loader.load()
        assert cfg is not None
        assert isinstance(cfg, GlobalConfig)

    def test_env_overrides_yaml(self, monkeypatch):
        monkeypatch.setenv("KASRA_ENGINE__MAX_CONCURRENT_RULES", "100")
        # Without env, default is 20
        cfg = GlobalConfig()
        assert cfg.engine.max_concurrent_rules == 100


# ======================================================================
# ChunkBuffer
# ======================================================================

class TestChunkBuffer:
    def test_append_and_content(self):
        buf = ChunkBuffer()
        buf.append("hello ")
        buf.append("world")
        assert "hello world" in buf.content

    def test_clear(self):
        buf = ChunkBuffer()
        buf.append("hello world")
        buf._buffer.clear()
        buf._total_chars = 0
        assert buf.content == ""

    def test_mark_complete(self):
        buf = ChunkBuffer()
        buf.mark_complete()
        assert buf.is_complete

    def test_flush_ready(self):
        buf = ChunkBuffer()
        assert buf.flush_ready() is None  # no boundary detector

    def test_unflushed_content(self):
        buf = ChunkBuffer()
        buf.append("hello world")
        assert buf.unflushed == "hello world"

    def test_total_chars(self):
        buf = ChunkBuffer()
        buf.append("hello")
        buf.append(" world")
        assert buf.total_chars == 11

    def test_flushed_pos(self):
        buf = ChunkBuffer()
        buf.append("hello")
        assert buf.flushed_pos == 0

    def test_content_property(self):
        buf = ChunkBuffer()
        buf.append("test content")
        assert buf.content == "test content"

    def test_append_after_complete(self):
        buf = ChunkBuffer()
        buf.mark_complete()
        buf.append("should be ignored")
        assert buf.content == ""


# ======================================================================
# Hook ABC
# ======================================================================

class TestHookABC:
    def test_hook_subclass(self):
        class MyHook(Hook):
            pass

        h = MyHook()
        assert h.name == "MyHook"

    def test_lifecycle_methods_defaults(self):
        class MyHook(Hook):
            pass

        h = MyHook()
        h.before_detect("content", None)
        h.after_detect(AggregatedResult(), None)
        h.before_rule("I-01", "content", None)
        h.after_rule(DetectionResult(
            rule_id="I-01", rule_name="A", severity=Severity.P0, action=ActionType.BLOCK,
        ), None)
        h.before_action("block", "content", None)
        h.after_action("block", "content", None)


# ======================================================================
# HookRegistry
# ======================================================================

class TestHookRegistry:
    def test_register(self):
        reg = HookRegistry()
        h = MyTestHook()
        reg.register(h)
        assert reg.count == 1

    def test_unregister(self):
        reg = HookRegistry()
        h = MyTestHook()
        reg.register(h)
        reg.unregister(h)
        assert reg.count == 0

    def test_clear(self):
        reg = HookRegistry()
        reg.register(MyTestHook())
        reg.register(MyTestHook())
        reg.clear()
        assert reg.count == 0

    def test_hooks_property(self):
        reg = HookRegistry()
        h = MyTestHook()
        reg.register(h)
        hooks = reg.hooks
        assert len(hooks) == 1

    def test_dispatch_error_does_not_block(self):
        reg = HookRegistry()
        reg.register(BrokenHook())
        h2 = MyTestHook()
        reg.register(h2)
        reg.before_detect("content", None)
        assert h2.called_before_detect


class MyTestHook(Hook):
    def __init__(self):
        self.called_before_detect = False

    def before_detect(self, content, context=None):
        self.called_before_detect = True


class BrokenHook(Hook):
    def before_detect(self, content, context=None):
        raise RuntimeError("I am broken")


# ======================================================================
# MetricsCollector
# ======================================================================

class TestMetricsCollector:
    def test_initial_snapshot(self):
        mc = MetricsCollector()
        s = mc.snapshot()
        assert s["total_detections"] == 0
        assert s["avg_latency_ms"] == 0.0

    def test_tracks_detections(self):
        mc = MetricsCollector()
        mc.before_detect("test", None)
        result = AggregatedResult(execution_time_ms=10.0)
        mc.after_detect(result, None)
        s = mc.snapshot()
        assert s["total_detections"] == 1
        assert s["avg_latency_ms"] > 0

    def test_reset(self):
        mc = MetricsCollector()
        mc.before_detect("test", None)
        result = AggregatedResult(execution_time_ms=5.0)
        mc.after_detect(result, None)
        mc.reset()
        s = mc.snapshot()
        assert s["total_detections"] == 0
