"""Unit tests for matchers: ReMatcher, KeywordMatcher, EntropyMatcher, base."""

from __future__ import annotations

import pytest
import re

from kasra.matchers.base import PatternMatcher
from kasra.matchers.regex_matcher import ReMatcher
from kasra.matchers.keyword_matcher import KeywordMatcher
from kasra.matchers.entropy_matcher import EntropyMatcher
from kasra.models.rule import PatternDefinition
from kasra.models.enums import PatternType


# ======================================================================
# PatternMatcher ABC
# ======================================================================

class TestPatternMatcherABC:
    def test_cannot_instantiate(self):
        with pytest.raises(TypeError):
            PatternMatcher()  # abstract

    def test_base_match_all_delegates_to_match(self):
        """Default match_all returns single-element list if match returns non-None."""
        class ConcreteMatcher(PatternMatcher):
            def match(self, content, pattern):
                if content == "match":
                    from kasra.models.result import MatchResult
                    return MatchResult(rule_id="", pattern_index=0, pattern_type="regex",
                                       pattern_value="test", confidence=1.0)
                return None

        m = ConcreteMatcher()
        results = m.match_all("match", PatternDefinition(type=PatternType.REGEX, value="test"))
        assert len(results) == 1
        results = m.match_all("no_match", PatternDefinition(type=PatternType.REGEX, value="test"))
        assert len(results) == 0

    def test_validate_default(self):
        class ConcreteMatcher(PatternMatcher):
            def match(self, content, pattern):
                return None

        m = ConcreteMatcher()
        m.validate(PatternDefinition(type=PatternType.REGEX, value="test"))  # should not raise


# ======================================================================
# ReMatcher
# ======================================================================

class TestReMatcher:
    def make_pat(self, value, confidence=0.7):
        return PatternDefinition(type=PatternType.REGEX, value=value, confidence=confidence)

    def test_match_found(self):
        m = ReMatcher()
        result = m.match("hello world", self.make_pat(r"world"))
        assert result is not None
        assert result.confidence == 0.7

    def test_match_not_found(self):
        m = ReMatcher()
        result = m.match("hello world", self.make_pat(r"zzzzz"))
        assert result is None

    def test_match_all_multiple(self):
        m = ReMatcher()
        results = m.match_all("aaa bbb aaa ccc aaa", self.make_pat(r"aaa"))
        assert len(results) >= 1

    def test_match_all_max_matches(self):
        m = ReMatcher()
        results = m.match_all("a a a a a", self.make_pat(r"a"), max_matches=2)
        total_spans = sum(len(r.spans) for r in results)
        assert total_spans <= 2

    def test_empty_content(self):
        m = ReMatcher()
        assert m.match("", self.make_pat(r".")) is None
        assert m.match_all("", self.make_pat(r".")) == []

    def test_invalid_regex_caught_by_dispatcher(self):
        """Invalid regex should be caught by MatcherDispatcher."""
        from kasra.core.runner import MatcherDispatcher
        m = MatcherDispatcher()
        results = m.match("test", self.make_pat(r"["))
        assert results == []  # Dispatcher catches and returns empty

    def test_validate_invalid(self):
        """Validation should raise on invalid regex."""
        m = ReMatcher()
        from kasra.exceptions.errors import PatternCompileError
        with pytest.raises((PatternCompileError, re.error)):
            m.validate(self.make_pat(r"["))


# ======================================================================
# KeywordMatcher
# ======================================================================

class TestKeywordMatcher:
    def make_pat(self, value, confidence=0.7):
        return PatternDefinition(type=PatternType.KEYWORD, value=value, confidence=confidence)

    def test_match_found(self):
        m = KeywordMatcher()
        result = m.match("hello world", self.make_pat("world"))
        assert result is not None

    def test_match_not_found(self):
        m = KeywordMatcher()
        result = m.match("hello world", self.make_pat("zzzzz"))
        assert result is None

    def test_match_all_multiple(self):
        m = KeywordMatcher()
        results = m.match_all("aaa bbb aaa ccc aaa", self.make_pat("aaa"))
        assert len(results) >= 1
        all_spans = [s for r in results for s in r.spans]
        assert len(all_spans) == 3

    def test_match_all_max_matches(self):
        m = KeywordMatcher()
        results = m.match_all("a a a a a", self.make_pat("a"), max_matches=2)
        all_spans = [s for r in results for s in r.spans]
        assert len(all_spans) <= 2

    def test_case_insensitive_by_default(self):
        m = KeywordMatcher()
        result = m.match("HELLO WORLD", self.make_pat("hello"))
        assert result is not None

    def test_empty_content(self):
        m = KeywordMatcher()
        assert m.match("", self.make_pat("a")) is None
        assert m.match_all("", self.make_pat("a")) == []

    def test_unicode_keyword(self):
        m = KeywordMatcher()
        result = m.match("café", self.make_pat("café"))
        assert result is not None

    def test_overlapping_dedup(self):
        m = KeywordMatcher()
        results = m.match_all("aaaa", self.make_pat("aa"))
        # Should not duplicate overlapping spans
        all_spans = [s for r in results for s in r.spans]
        # Each unique position should appear once
        positions = {(s.start, s.end) for s in all_spans}
        assert len(positions) == len(all_spans)

    def test_validate_empty(self):
        m = KeywordMatcher()
        with pytest.raises(ValueError):
            m.validate(self.make_pat(""))


# ======================================================================
# EntropyMatcher
# ======================================================================

class TestEntropyMatcher:
    def make_pat(self, confidence=4.5, min_length=12):
        return PatternDefinition(
            type=PatternType.ENTROPY, value="",
            confidence=confidence,
            min_length=min_length,
        )

    def test_high_entropy_secret(self):
        m = EntropyMatcher()
        # A random-looking base64-like string
        secret = "aB3dEfGhIjKlMnOpQrStUvWxYz"  # ~26 chars, high entropy
        result = m.match(secret, self.make_pat())
        assert result is not None

    def test_low_entropy_text(self):
        m = EntropyMatcher()
        # Natural language should not match
        text = "hello world how are you doing today this is a normal sentence"
        result = m.match(text, self.make_pat())
        assert result is None

    def test_too_short(self):
        m = EntropyMatcher()
        result = m.match("abc", self.make_pat(min_length=12))
        assert result is None

    def test_repeated_chars(self):
        m = EntropyMatcher()
        result = m.match("aaaaaaabbbbbbbccccccccdddddddd", self.make_pat())
        assert result is None  # Low unique char count

    def test_empty_content(self):
        m = EntropyMatcher()
        assert m.match("", self.make_pat()) is None
        assert m.match_all("", self.make_pat()) == []

    def test_match_all_limit(self):
        m = EntropyMatcher()
        # Long high-entropy content
        content = "aB3dEfGhIjKlMnOpQrStUvWxYz0123456789+/" * 20
        results = m.match_all(content, self.make_pat(), max_matches=3)
        assert len(results) <= 3

    def test_custom_threshold(self):
        m = EntropyMatcher()
        # Very high threshold — nothing should match natural text
        result = m.match("hello world test data some normal words here", self.make_pat(confidence=7.0))
        assert result is None

    def test_shannon_entropy_value(self):
        """Verify _shannon_entropy returns correct values."""
        # A string with all same chars has 0 entropy
        e = EntropyMatcher._shannon_entropy("aaaa")
        assert e == 0.0

        # Maximum entropy for uniform distribution over N chars
        e = EntropyMatcher._shannon_entropy("abcd")
        assert e == 2.0  # log2(4) = 2

        # Empty string
        e = EntropyMatcher._shannon_entropy("")
        assert e == 0.0

    def test_looks_like_natural(self):
        """Natural language heuristic."""
        assert EntropyMatcher._looks_like_natural("hello world this is text")
        assert not EntropyMatcher._looks_like_natural("aB3dEfGhIjKlMnOpQrStUv")

    def test_validate_valid(self):
        m = EntropyMatcher()
        m.validate(self.make_pat(confidence=4.5, min_length=12))

    def test_validate_invalid_threshold(self):
        m = EntropyMatcher()
        with pytest.raises(ValueError):
            m.validate(self.make_pat(confidence=9.0))  # >8.0

    def test_validate_invalid_min_length(self):
        m = EntropyMatcher()
        with pytest.raises(ValueError):
            m.validate(self.make_pat(confidence=4.5, min_length=1))  # <3
