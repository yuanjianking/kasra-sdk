"""Kasra L3 Rule Engine — Luhn checksum validator for credit-card numbers.

Implements the Luhn algorithm (ISO/IEC 7812-1) for credit-card number
validation, plus issuer identification number (IIN) range detection
for major card networks.
"""

from __future__ import annotations

import re
from typing import ClassVar

from kasra.analyzers.base import Analyzer
from kasra.analyzers.context import AnalysisContext, LuhnValidation


# IIN ranges for major card networks
# See: https://en.wikipedia.org/wiki/Payment_card_number#Issuer_identification_number_(IIN)
_CARD_NETWORKS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^4[0-9]"), "Visa"),
    (re.compile(r"^5[1-5][0-9]"), "MasterCard"),
    (re.compile(r"^2[2-7][0-9]"), "MasterCard"),
    (re.compile(r"^3[47][0-9]"), "American Express"),
    (re.compile(r"^6011|65[0-9]"), "Discover"),
    (re.compile(r"^622[0-9]"), "Discover"),
    (re.compile(r"^64[4-9][0-9]"), "Discover"),
    (re.compile(r"^36|38|300[0-5]"), "Diners Club"),
    (re.compile(r"^35[2-8][0-9]"), "JCB"),
    (re.compile(r"^62[0-9]"), "China UnionPay"),
    (re.compile(r"^50|56|57|58|59|60|61|62|63|64|65|66|67|68|69"), "Maestro"),
]


class LuhnValidator(Analyzer):
    """Validates credit-card numbers using the Luhn algorithm.

    Also detects the card network from the IIN prefix.

    Usage::

        validator = LuhnValidator()
        result = validator.validate("4111-1111-1111-1111")
        assert result.is_valid
        assert result.card_network == "Visa"
    """

    layer: int = 3
    name: str = "luhn_validator"

    # Std validation: length 12-19 digits
    _VALID_LENGTHS = range(12, 20)

    def analyze(self, content: str, context: AnalysisContext) -> AnalysisContext:
        """Luhn validation runs per-rule in :class:`RuleRunner` via ``_apply_luhn_validation``.

        This analyzer method is a no-op here because Luhn validation requires
        a specific rule context (it's invoked from the runner).
        """
        return context

    def validate(self, candidate: str) -> LuhnValidation:
        """Validate a single credit-card candidate.

        Args:
            candidate: The raw matched text (may include spaces/dashes).

        Returns:
            A :class:`LuhnValidation` with ``is_valid`` and ``card_network``.
        """
        # Normalise: keep only digits
        normalized = re.sub(r"[^\d]", "", candidate)
        raw = candidate.strip()

        # Basic checks
        if not normalized or len(normalized) not in self._VALID_LENGTHS:
            return LuhnValidation(
                raw_candidate=raw,
                normalized=normalized,
                is_valid=False,
                card_network=None,
            )

        # Luhn algorithm
        is_valid = self._luhn_checksum(normalized)

        # Card network detection
        network = self._detect_network(normalized) if is_valid else None

        return LuhnValidation(
            raw_candidate=raw,
            normalized=normalized,
            is_valid=is_valid,
            card_network=network,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _luhn_checksum(digits: str) -> bool:
        """Compute and verify the Luhn checksum.

        Standard algorithm:
        1. From rightmost digit, double every second digit.
        2. If doubling produces >9, subtract 9.
        3. Sum all digits.  Valid if sum % 10 == 0.
        """
        total = 0
        double = False
        for d in reversed(digits):
            val = ord(d) - 48  # faster than int(d)
            if double:
                val *= 2
                if val > 9:
                    val -= 9
            total += val
            double = not double
        return total % 10 == 0

    @staticmethod
    def _detect_network(digits: str) -> str | None:
        """Detect card network from IIN prefix."""
        for pattern, name in _CARD_NETWORKS:
            if pattern.match(digits):
                return name
        return None
