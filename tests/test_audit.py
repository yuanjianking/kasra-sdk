"""Unit tests for audit/logger, audit/exporters, audit/formatters."""

from __future__ import annotations

import json
import io
import os
import tempfile

import pytest

from kasra.audit.logger import AuditLogger
from kasra.audit.exporters import ConsoleExporter, FileExporter
from kasra.audit.formatters import JSONLFormatter
from kasra.models.enums import Severity, ActionType
from kasra.models.result import AggregatedResult, DetectionResult
from kasra.models.events import AuditEvent


# ======================================================================
# JSONLFormatter
# ======================================================================

class TestJSONLFormatter:
    def test_format_string(self):
        f = JSONLFormatter()
        event = AuditEvent(
            event_id="evt-1",
            stage="input", rule_id="I-01", rule_name="Test",
            severity="P0", action="block",
        )
        output = f.format(event)
        assert isinstance(output, str)
        assert "evt-1" in output
        assert "I-01" in output

    def test_format_valid_json(self):
        f = JSONLFormatter()
        event = AuditEvent(
            event_id="test-json",
            stage="output", rule_id="O-01", rule_name="A",
            severity="P1", action="warn",
        )
        parsed = json.loads(f.format(event))
        assert parsed["event_id"] == "test-json"
        assert parsed["stage"] == "output"

    def test_multiple_events(self):
        f = JSONLFormatter()
        events = [
            AuditEvent(event_id="e1", stage="input", rule_id="I-01",
                       rule_name="A", severity="P0", action="block"),
            AuditEvent(event_id="e2", stage="output", rule_id="O-01",
                       rule_name="B", severity="P1", action="warn"),
        ]
        for event in events:
            parsed = json.loads(f.format(event))
            assert "event_id" in parsed


# ======================================================================
# ConsoleExporter
# ======================================================================

class TestConsoleExporter:
    def test_write_to_stderr(self):
        exporter = ConsoleExporter(stream="stderr")
        # Uses sys.stderr for stderr
        import sys
        assert exporter._stream_name == "stderr"
        assert exporter._stream is sys.stderr

    def test_write_to_stdout(self):
        exporter = ConsoleExporter(stream="stdout")
        import sys
        assert exporter._stream_name == "stdout"
        assert exporter._stream is sys.stdout


# ======================================================================
# FileExporter
# ======================================================================

class TestFileExporter:
    def test_write_to_temp_file(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            path = tmp.name
        try:
            exporter = FileExporter(path=path)
            from kasra.models.events import AuditEvent
            e1 = AuditEvent(event_id="e1", stage="input", rule_id="I-01", rule_name="A", severity="P0", action="block")
            e2 = AuditEvent(event_id="e2", stage="input", rule_id="I-02", rule_name="B", severity="P1", action="warn")
            exporter.export(e1)
            exporter.export(e2)
            exporter.close()

            with open(path) as f:
                lines = f.readlines()
            assert len(lines) == 2
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_default_path(self):
        exporter = FileExporter(path="/tmp/test-exporter.jsonl")
        assert exporter is not None
        exporter.close()
        if os.path.exists("/tmp/test-exporter.jsonl"):
            os.unlink("/tmp/test-exporter.jsonl")

    def test_write_closed_handle(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            path = tmp.name
        try:
            from kasra.models.events import AuditEvent
            exporter = FileExporter(path=path)
            ev = AuditEvent(event_id="e1", stage="input", rule_id="I-01", rule_name="A", severity="P0", action="block")
            exporter.export(ev)
            exporter.close()
            # After close, should not raise
            exporter.export(ev)
        finally:
            if os.path.exists(path):
                os.unlink(path)


# ======================================================================
# AuditLogger
# ======================================================================

class TestAuditLogger:
    def test_create_no_exporters(self):
        logger = AuditLogger()
        assert logger is not None
        # exporters can be None or [] depending on how initialized
        assert logger.exporters is None or logger.exporters == []

    def test_create_with_exporters(self):
        exporter = MockExporter()
        logger = AuditLogger(exporters=[exporter])
        assert logger.exporters is not None

    def test_start_stop(self):
        logger = AuditLogger()
        logger.start()  # Should not raise
        logger.stop()   # Should not raise

    def test_start_stop_with_exporter(self):
        from kasra.audit.exporters import ConsoleExporter
        exporter = ConsoleExporter(stream="stderr")
        logger = AuditLogger(exporters=[exporter])
        logger.start()
        logger.stop()

    def test_max_queue_size_default(self):
        logger = AuditLogger()
        assert hasattr(logger, "max_queue_size")

    def test_batch_write_interval_default(self):
        logger = AuditLogger()
        assert hasattr(logger, "batch_write_interval")


class MockExporter:
    """Mock exporter for testing AuditLogger."""
    def __init__(self):
        self.written = []

    def write(self, line: str) -> None:
        self.written.append(line)

    def close(self) -> None:
        pass
