"""Kasra L3 Rule Engine — Audit logger.

The :class:`AuditLogger` uses a bounded queue and a background worker
to write audit events asynchronously without blocking the detection
pipeline.

Usage::

    logger = AuditLogger()
    logger.start()
    logger.log(rule_id="I-06", severity="P0", ...)
    # ... pipelines run ...
    logger.stop()  # flush and shutdown
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from queue import Empty, Full, Queue
from typing import Any
from uuid import uuid4

from kasra.audit.exporters import AuditExporter, ConsoleExporter, FileExporter
from kasra.utils.time import utcnow
from kasra.audit.formatters import JSONLFormatter
from kasra.exceptions.errors import AuditError
from kasra.models.events import AuditEvent
from kasra.models.result import AggregatedResult

logger = logging.getLogger("kasra.audit")


@dataclass
class AuditLogger:
    """Async audit logger with bounded queue and background worker.

    The logger accumulates events in a thread-safe queue and writes them
    in batches via the configured exporters.

    Args:
        exporters: List of exporters to write to.  Defaults to a console
            exporter and a file exporter at ``/var/log/kasra/audit.jsonl``.
        max_queue_size: Maximum number of events to queue before blocking.
        batch_write_interval: Seconds between batch flushes.
    """

    exporters: list[AuditExporter] | None = None
    max_queue_size: int = 10_000
    batch_write_interval: float = 2.0

    _queue: Queue = field(default_factory=lambda: Queue(maxsize=10_000))
    _worker: threading.Thread | None = None
    _stop_event: threading.Event = field(default_factory=threading.Event)
    _started: bool = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background worker thread."""
        if self._started:
            return

        if self.exporters is None:
            self.exporters = [
                ConsoleExporter(),
                FileExporter(path="kasra-audit.jsonl"),  # CWD by default; configurable
            ]

        self._stop_event.clear()
        self._worker = threading.Thread(
            target=self._worker_loop,
            name="kasra-audit",
            daemon=True,
        )
        self._worker.start()
        self._started = True

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the worker to stop and flush remaining events.

        Args:
            timeout: Maximum seconds to wait for the worker to finish.
        """
        if not self._started:
            return
        self._stop_event.set()
        if self._worker is not None:
            self._worker.join(timeout=timeout)
            self._worker = None
        self._started = False

        # Final flush
        self._flush_all()

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log(self, event: AuditEvent) -> None:
        """Enqueue an audit event for async writing.

        Args:
            event: The ``AuditEvent`` to log.

        If the queue is full, the event is dropped and a warning is logged.
        """
        if not self._started:
            logger.warning("AuditLogger not started — dropping event")
            return
        try:
            self._queue.put_nowait(event)
        except Full:
            logger.warning("Audit queue full — dropping event")

    def log_result(
        self,
        result: AggregatedResult,
        stage: str = "input",
        user_id: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        source: str = "api",
    ) -> None:
        """Log all triggered rules from an ``AggregatedResult`` as events.

        Convenience method that creates one ``AuditEvent`` per triggered
        rule and enqueues them.
        """
        for det_result in result.triggered_rules:
            event = AuditEvent(
                event_id=str(uuid4()),
                timestamp=utcnow(),
                stage=stage,
                rule_id=det_result.rule_id,
                rule_name=det_result.rule_name,
                severity=det_result.severity,
                action=det_result.action,
                user_id=user_id,
                session_id=session_id,
                request_id=request_id,
                source=source,
                content_snippet=(
                    det_result.matches[0].matched_text[:200]
                    if det_result.matches
                    else None
                ),
                content_length=0,
                match_count=det_result.match_count,
                matched_spans=[
                    {"start": s.start, "end": s.end, "matched": s.matched[:100]}
                    for m in det_result.matches
                    for s in m.spans
                ],
                action_taken=result.overall_action.value if result.triggered_rules else "none",
                gdpr_relevant=False,  # category not on DetectionResult; resolve via rule_id lookup if needed
            )
            self.log(event)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _worker_loop(self) -> None:
        """Background loop: drain queue and write batches."""
        batch: list[AuditEvent] = []

        while not self._stop_event.is_set():
            try:
                event = self._queue.get(timeout=self.batch_write_interval)
                batch.append(event)

                # Drain any additional events available immediately
                while len(batch) < 100:
                    try:
                        batch.append(self._queue.get_nowait())
                    except Empty:
                        break

                # Write batch
                self._write_batch(batch)
                batch.clear()

            except Empty:
                # Timeout — flush any partial batch and loop
                if batch:
                    self._write_batch(batch)
                    batch.clear()

        # Final drain
        while True:
            try:
                batch.append(self._queue.get_nowait())
            except Empty:
                break
        if batch:
            self._write_batch(batch)

    def _write_batch(self, events: list[AuditEvent]) -> None:
        """Write a batch of events to all exporters."""
        for exporter in self.exporters or []:
            try:
                for event in events:
                    exporter.export(event)
            except AuditError:
                logger.exception("Audit export failed")

    def _flush_all(self) -> None:
        """Flush all exporters."""
        for exporter in self.exporters or []:
            try:
                exporter.flush()
            except AuditError:
                logger.exception("Audit flush failed")
