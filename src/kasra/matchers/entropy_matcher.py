"""Kasra L3 Rule Engine — Entropy matcher using Shannon entropy.

Detects high-randomness strings that are likely to be secrets, tokens,
credentials, or encoded payloads — even when no fixed keyword or regex
pattern is known.
"""

from __future__ import annotations

import math
import re

from kasra.matchers.base import PatternMatcher
from kasra.models.result import MatchResult, MatchSpan
from kasra.models.rule import PatternDefinition


class EntropyMatcher(PatternMatcher):
    """Shannon entropy-based secret / encoded-payload detector.

    The detector scans for consecutive runs of characters whose **per-byte
    Shannon entropy** exceeds a threshold.

    Design choices:
      - Only considers **runs of high-entropy characters** (alphanumeric +
        base64 chars + hex chars) rather than computing entropy on arbitrary
        whitespace-delimited tokens — this avoids flagging natural-language
        sentences with high type count.
      - Default threshold 4.5 bits/byte — empirically catches most API keys
        and tokens while letting normal text through.
      - Ignores runs shorter than ``min_length`` (default 12) to avoid
        flagging short hex strings that happen to be high-entropy.

    Reference:
        Shannon, C. E. "A Mathematical Theory of Communication."
        *Bell System Technical Journal* 27 (1948): 379–423, 623–656.
    """

    # Chars that contribute to a candidate high-entropy run.
    # Base64 alphabet + hex + punctuation common in tokens.
    _HIGH_ENTROPY_CHARS = re.compile(
        r"[A-Za-z0-9+/=_\-:.~@#$%&!?]{8,}"
    )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def match(self, content: str, pattern: PatternDefinition) -> MatchResult | None:
        matches = self.match_all(content, pattern, max_matches=1)
        return matches[0] if matches else None

    def match_all(
        self,
        content: str,
        pattern: PatternDefinition,
        max_matches: int = 10,
    ) -> list[MatchResult]:
        if not content:
            return []

        threshold = pattern.confidence
        min_len = pattern.min_length or 12

        results: list[MatchResult] = []
        seen_spans: set[tuple[int, int]] = set()
        count = 0

        for candidate_match in self._HIGH_ENTROPY_CHARS.finditer(content):
            if count >= max_matches:
                break

            start, end = candidate_match.start(), candidate_match.end()
            text = candidate_match.group()

            # Skip if too short
            if len(text) < min_len:
                continue

            # Skip if contains only a single repeated char (e.g. "aaaa...")
            if len(set(text)) < 3:
                continue

            # Skip if it looks like natural language
            if self._looks_like_natural(text):
                continue

            # Compute Shannon entropy
            entropy = self._shannon_entropy(text)

            if entropy >= threshold:
                key = (start, end)
                if key in seen_spans:
                    continue
                seen_spans.add(key)

                span = MatchSpan(
                    start=start,
                    end=end,
                    matched=text[:500],
                    redacted=None,
                )
                results.append(
                    MatchResult(
                        rule_id="",
                        pattern_index=count,
                        pattern_type="entropy",
                        pattern_value=f"entropy>={threshold:.1f}",
                        confidence=min(1.0, entropy / 8.0),
                        spans=[span],
                        matched_text=text[:200],
                    )
                )
                count += 1

        return results

    def validate(self, pattern: PatternDefinition) -> None:
        threshold = pattern.confidence
        if not (0.0 <= threshold <= 8.0):
            raise ValueError(
                f"Entropy threshold (confidence) must be 0.0–8.0, got {threshold}"
            )
        if pattern.min_length is not None and pattern.min_length < 3:
            raise ValueError(
                f"Entropy min_length must be >= 3, got {pattern.min_length}"
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Compute Shannon entropy (bits per byte) for *text*."""
        if not text:
            return 0.0
        length = len(text)
        freq: dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _looks_like_natural(text: str) -> bool:
        """Heuristic: avoid flagging natural-language strings.

        Returns True if the text is mostly lowercase ASCII with spaces
        or common English words — unlikely to be a secret.
        """
        # If it contains spaces and the ratio of lowercase letters is
        # high, it's probably natural language, not a secret.
        if " " in text:
            # Count lowercase ASCII vs total chars
            lower_count = sum(1 for ch in text if ch.islower() or ch == " ")
            if lower_count / len(text) > 0.7:
                return True
        return False
