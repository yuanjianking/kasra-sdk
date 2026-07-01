"""Kasra L3 Rule Engine — Cross-rule correlation.

Layer 4 of the detection architecture.  Implements two dead-config
features that were declared in ``RuleConfig`` but never processed:

1. **context_boost** — proximity-based severity override.
   When rule A triggers with ``config.context_boost.proximity_rules``,
   and any of those proximity rules also triggered with matches near
   rule A's matches, the severity is escalated.

   Used by: I-19 (Date of Birth — boosts to P1 when near I-12 or I-18).

2. **link_to_rules** — cross-trigger evidence linking.
   When rule A triggers with ``config.link_to_rules`` pointing to
   rule B, and rule B also triggered, an evidence-chain entry is
   added linking the two findings.

   Used by: I-38 → I-37, I-48 → I-42.
"""

from __future__ import annotations

import re
from typing import Any

from kasra.analyzers.context import AnalysisContext, EvidenceItem
from kasra.models.enums import Severity
from kasra.models.result import AggregatedResult
from kasra.models.rule import RuleDefinition


class CrossRuleCorrelator:
    """Cross-rule evidence correlation (Layer 4).

    Processes ``context_boost`` and ``link_to_rules`` configuration
    across all triggered rules in an aggregation.
    """

    def correlate(
        self,
        aggregated: AggregatedResult,
        rules: list[RuleDefinition],
        context: AnalysisContext,
    ) -> None:
        """Run cross-rule correlation on an aggregated result.

        Args:
            aggregated: The aggregated result with triggered rules.
            rules: All rules (triggered + non-triggered) for reference.
            context: The analysis context from earlier layers.
        """
        if not aggregated.triggered_rules:
            return

        # Build lookup: rule_id -> DetectionResult
        triggered_map = {r.rule_id: r for r in aggregated.triggered_rules}

        # Build lookup: rule_id -> RuleDefinition
        rule_map = {r.id: r for r in rules}

        # 1. Process context_boost
        self._process_context_boost(aggregated, triggered_map, rule_map, context)

        # 2. Process link_to_rules
        self._process_link_to_rules(aggregated, triggered_map, rule_map, context)

        # 3. Process modifier_rule / severity_reduction
        self._process_modifier_rules(aggregated, triggered_map, rule_map, context)

    # ------------------------------------------------------------------
    # context_boost
    # ------------------------------------------------------------------

    def _process_context_boost(
        self,
        aggregated: AggregatedResult,
        triggered_map: dict[str, Any],
        rule_map: dict[str, RuleDefinition],
        context: AnalysisContext,
    ) -> None:
        """Apply proximity-based severity boosts."""
        for rule_id, result in triggered_map.items():
            rule_def = rule_map.get(rule_id)
            if not rule_def:
                continue

            boost_config = rule_def.config.context_boost
            if not boost_config:
                continue

            proximity_rules = boost_config.get("proximity_rules", [])
            if not proximity_rules:
                continue

            severity_override = boost_config.get("severity_override")
            proximity_window = boost_config.get("proximity_window", 500)

            # Check if any proximity rule also triggered
            triggered_proximity = [
                rid for rid in proximity_rules if rid in triggered_map
            ]
            if not triggered_proximity:
                continue

            # Check proximity of matches
            our_spans = self._collect_spans(result)
            if not our_spans:
                continue

            for prox_rule_id in triggered_proximity:
                prox_result = triggered_map[prox_rule_id]
                prox_spans = self._collect_spans(prox_result)

                if not prox_spans:
                    continue

                # Check if any of our spans are near any of their spans
                near = False
                for our_start, our_end in our_spans:
                    for prox_start, prox_end in prox_spans:
                        distance = min(
                            abs(our_end - prox_start),
                            abs(prox_end - our_start),
                            abs(our_start - prox_end),
                            abs(prox_start - our_end),
                        )
                        if distance <= proximity_window:
                            near = True
                            break
                    if near:
                        break

                if near and severity_override:
                    # Apply severity override
                    new_sev = Severity(severity_override)
                    result.severity = new_sev

                    # Add evidence
                    evidence = EvidenceItem(
                        rule_id=rule_id,
                        reason=f"Severity boosted to {severity_override} due to proximity with {prox_rule_id}",
                        matching_text="",
                        confidence=1.0,
                        source_layer="correlation",
                    )
                    result.evidence.append(evidence)
                    context.evidence_chain.append(evidence)

                    # Update aggregated severity
                    from kasra.utils.severity import SEVERITY_RANK
                    current_rank = SEVERITY_RANK.get(aggregated.overall_severity, 99)
                    new_rank = SEVERITY_RANK.get(new_sev, 99)
                    if new_rank < current_rank:
                        aggregated.overall_severity = new_sev

    # ------------------------------------------------------------------
    # link_to_rules
    # ------------------------------------------------------------------

    def _process_link_to_rules(
        self,
        aggregated: AggregatedResult,
        triggered_map: dict[str, Any],
        rule_map: dict[str, RuleDefinition],
        context: AnalysisContext,
    ) -> None:
        """Add evidence-chain entries for linked rules."""
        for rule_id, result in triggered_map.items():
            rule_def = rule_map.get(rule_id)
            if not rule_def:
                continue

            linked = rule_def.config.link_to_rules
            if not linked:
                continue

            triggered_linked = [rid for rid in linked if rid in triggered_map]
            if not triggered_linked:
                continue

            for linked_rule_id in triggered_linked:
                linked_result = triggered_map[linked_rule_id]
                evidence = EvidenceItem(
                    rule_id=rule_id,
                    reason=f"Correlated with {linked_rule_id} ({linked_result.rule_name}) — linked by rule config",
                    matching_text="",
                    confidence=1.0,
                    source_layer="correlation",
                )
                result.evidence.append(evidence)
                context.evidence_chain.append(evidence)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Modifier rules (severity_reduction)
    # ------------------------------------------------------------------

    def _process_modifier_rules(
        self,
        aggregated: AggregatedResult,
        triggered_map: dict[str, Any],
        rule_map: dict[str, RuleDefinition],
        context: AnalysisContext,
    ) -> None:
        """Apply severity_reduction from modifier rules (I-45, I-46).

        When a modifier rule triggers, it can reduce the severity of
        other rules listed in its ``severity_reduction`` config.
        """
        for rule_id, result in list(triggered_map.items()):
            rule_def = rule_map.get(rule_id)
            if not rule_def:
                continue

            sev_red = rule_def.config.severity_reduction
            if not sev_red:
                continue

            for target_rule_id, reduced_sev_str in sev_red.items():
                target_result = triggered_map.get(target_rule_id)
                if not target_result:
                    continue

                # Only reduce severity if target is less severe than override
                from kasra.utils.severity import SEVERITY_RANK
                reduced_sev = Severity(reduced_sev_str)
                current_rank = SEVERITY_RANK.get(target_result.severity, 99)
                reduced_rank = SEVERITY_RANK.get(reduced_sev, 99)

                if reduced_rank < current_rank:
                    # Apply reduction
                    target_result.severity = reduced_sev

                    evidence = EvidenceItem(
                        rule_id=rule_id,
                        reason=f"Reduced {target_rule_id} severity to {reduced_sev_str} via modifier rule {rule_id}",
                        matching_text="",
                        confidence=1.0,
                        source_layer="correlation",
                    )
                    result.evidence.append(evidence)
                    context.evidence_chain.append(evidence)

    @staticmethod
    def _collect_spans(result: Any) -> list[tuple[int, int]]:
        """Collect all (start, end) spans from a detection result's matches."""
        spans: list[tuple[int, int]] = []
        for match in result.matches:
            for span in match.spans:
                spans.append((span.start, span.end))
        return spans
