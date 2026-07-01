"""Kasra L3 Rule Engine — Output detection pipeline.

The output pipeline runs on AI-generated content **before** it is sent
to the user.  It detects:
  - Sensitive data leakage (PII, credentials, internal logic)
  - Policy violations in generated content
  - Prompt extraction / jailbreak responses

Streaming three-phase detection
-------------------------------
The output pipeline is designed for streaming (SSE) scenarios:

  **Phase 1 — Per-chunk (fast path):** As each chunk arrives, only
  lightweight regex and keyword matchers run on the delta.  No full
  pattern evaluation.

  **Phase 2 — At boundary:** When a natural boundary (sentence end,
  line break) is reached, full matchers (including entropy) run on
  the completed segment.

  **Phase 3 — End-of-stream:** When the stream ends, all matchers run
  on the complete accumulated content.

  **Retroactive redaction:** If a rule triggers after content has
  already been sent (Phase 3), the pipeline flags the emitted content
  for redaction — the caller is responsible for replacing it.

The base ``DetectionPipeline.run()`` is the **Phase 3** (end-of-stream)
scan.  Callers should use :class:`ChunkBuffer` + the phase methods
for streaming scenarios.
"""

from __future__ import annotations

from typing import Any

from kasra.core.pipeline import DetectionPipeline
from kasra.models.enums import PipelinePhase, Stage
from kasra.models.result import AggregatedResult, DetectionResult
from kasra.models.rule import RuleDefinition


class OutputDetectionPipeline(DetectionPipeline):
    """Output detection pipeline for AI-generated content.

    Usage (full-content scan)::

        pipeline = OutputDetectionPipeline(registry, runner)
        result = pipeline.run(ai_generated_text)

    Usage (streaming with phases)::

        from kasra.context.buffer import ChunkBuffer
        from kasra.preprocessing.chunker import BoundaryDetector

        buffer = ChunkBuffer(max_size=8192)
        detector = BoundaryDetector(mode="sentence")

        # Phase 1 + 2: accumulate and flush on boundaries
        for chunk in stream:
            buffer.append(chunk)
            boundary = buffer.flush_ready()
            if boundary is not None:
                segment = buffer.pop_flushed(boundary)
                pipeline.run_phase(segment, PipelinePhase.PHASE2_BOUNDARY)

        # Phase 3: scan everything
        buffer.mark_complete()
        final = pipeline.run(buffer.content)
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        # Track cumulative content length across streaming phases.
        # Reset before starting a new stream.
        self._streamed_content_length: int = 0

    def reset_stream_state(self) -> None:
        """Reset the cumulative content-length tracker.

        Call this before processing a new stream.
        """
        self._streamed_content_length = 0

    def get_rules(self) -> list[RuleDefinition]:
        """Return all enabled output-stage rules, ordered P0 → P1 → P2."""
        return self._registry.get_rules_for_stage(Stage.OUTPUT)

    # ------------------------------------------------------------------
    # Phase-based streaming detection
    # ------------------------------------------------------------------

    def run_phase(
        self,
        content: str,
        phase: PipelinePhase,
        preprocess: bool = True,
        **context_kwargs: Any,
    ) -> AggregatedResult:
        """Run detection for a specific streaming phase.

        Phase 1 runs regex + keyword only (fast path).
        Phase 2 runs all matchers.
        Phase 3 is equivalent to a full ``run()``.

        Args:
            content: The content segment to evaluate.
            phase: The streaming phase.
            preprocess: Whether to apply normalization.
            **context_kwargs: Additional context fields.

        Returns:
            An ``AggregatedResult`` for this segment.
        """
        # For Phase 3, delegate to the full run
        if phase == PipelinePhase.PHASE3_END_OF_STREAM:
            return self.run(content, preprocess=preprocess, **context_kwargs)

        # For Phase 1 & 2, skip preprocessing and only run lightweight checks
        if preprocess:
            content = self.preprocess(content)

        # Track cumulative content length across streaming phases
        # (so O-51 max_length fires even when each chunk is <50K)
        self._streamed_content_length += len(content)
        cumulative_len = self._streamed_content_length

        # Run analyzer pipeline (language detection, code blocks, data flow)
        analysis_context = self._analyzer_pipeline.execute(content)

        context = self.get_context(**context_kwargs)
        rules = self.get_rules()

        if not rules:
            return AggregatedResult()

        # Phase 1: only regex + keyword patterns (skip entropy and composite)
        # Phase 2: all matchers
        results: list[DetectionResult] = []
        for rule in rules:
            if not rule.enabled:
                continue
            # In Phase 1, skip rules that only use entropy/composite patterns
            if phase == PipelinePhase.PHASE1_FAST and not self._is_fast_rule(rule):
                continue
            results.append(self._runner.run_rule(
                content, rule, analysis_context=analysis_context,
            ))

        # Check no_pattern_match rules (O-51) against cumulative stream length
        # so max_length fires even when each individual chunk is <50K
        self._check_max_length_against_cumulative(rules, cumulative_len, results)

        aggregated = self._aggregate(results, rules, analysis_context)
        action_result = self._execute_action(content, aggregated, context)
        if action_result is not None:
            if action_result.blocked:
                aggregated.blocked = True
                aggregated.overall_action = action_result.action
        return aggregated

    def finalize(
        self,
        aggregated: AggregatedResult,
        action_result: Any,
    ) -> AggregatedResult:
        """Attach output-specific metadata."""
        if action_result is not None:
            aggregated.metadata = {
                "processed_content": action_result.content,
                "action_taken": action_result.action.value if hasattr(action_result, 'action') else None,
            }
        return aggregated

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_fast_rule(rule: RuleDefinition) -> bool:
        """Check if a rule only uses fast pattern types (regex + keyword).

        Rules that use ONLY ``regex`` or ``keyword`` patterns can run in
        Phase 1.  Rules with ``entropy`` or ``composite`` patterns must
        wait until Phase 2+.
        """
        for pattern in rule.detection.patterns:
            if pattern.type.value in ("entropy", "composite"):
                return False
        return True

    @staticmethod
    def _check_max_length_against_cumulative(
        rules: list[RuleDefinition],
        cumulative_len: int,
        results: list[DetectionResult],
    ) -> None:
        """For ``no_pattern_match`` rules with ``max_length``, inject a triggered
        result if the cumulative stream length exceeds the threshold even when
        the current segment did not.

        This ensures O-51 fires during Phase 1/2 when the total streamed
        content exceeds 50K, even if each individual chunk is under 50K.
        """
        for rule in rules:
            if not rule.enabled:
                continue
            if not (rule.config and rule.config.no_pattern_match and rule.config.max_length):
                continue
            # Already triggered by the segment check — skip
            if any(r.rule_id == rule.id and r.triggered for r in results):
                continue
            # Cumulative length exceeds threshold — inject triggered result
            if cumulative_len > rule.config.max_length:
                from kasra.analyzers.context import EvidenceItem
                from kasra.models.result import DetectionResult, MatchResult
                results.append(DetectionResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    action=rule.action,
                    triggered=True,
                    matches=[MatchResult(
                        rule_id=rule.id,
                        pattern_index=0,
                        pattern_type="config",
                        pattern_value=f"max_length={rule.config.max_length}",
                        confidence=1.0,
                        matched_text=f"Cumulative stream length {cumulative_len} exceeds max {rule.config.max_length}",
                    )],
                    evidence=[EvidenceItem(
                        rule_id=rule.id,
                        reason=f"Stream cumulative length {cumulative_len} > max_length={rule.config.max_length}",
                        matching_text=f"length={cumulative_len}",
                        confidence=1.0,
                        source_layer="semantic",
                    )],
                ))
