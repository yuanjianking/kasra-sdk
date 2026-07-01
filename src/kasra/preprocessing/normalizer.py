"""Kasra L3 Rule Engine — Content normalizer.

The :class:`ContentNormalizer` applies a configurable sequence of
transformations to raw text before rule evaluation:

  1. Unicode NFKC normalization
  2. Zero-width / invisible character stripping
  3. Control character sanitization (optional)
  4. Encoding detection / repair (via charset-normalizer)
"""

from __future__ import annotations

from kasra.exceptions.errors import NormalizationError
from kasra.utils.text import nfc_normalize, strip_control, strip_invisible


def _decode_bytes(raw: bytes, fallback: str = "utf-8") -> str:
    """Decode bytes to string, trying charset detection first."""
    try:
        import charset_normalizer  # type: ignore[import-untyped]
        result = charset_normalizer.from_bytes(raw)
        if result.best():
            return str(result.best())
    except (ImportError, Exception):
        pass
    return raw.decode(fallback, errors="replace")


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------

class ContentNormalizer:
    """Configurable text normalizer for pipeline pre-processing.

    Typical usage::

        normalizer = ContentNormalizer()
        clean = normalizer.normalize(raw_text)
    """

    def __init__(
        self,
        strip_invisible: bool = True,
        strip_control: bool = True,
        normalize_unicode: bool = True,
    ) -> None:
        self._strip_invisible = strip_invisible
        self._strip_control = strip_control
        self._normalize_unicode = normalize_unicode

    def normalize(self, text: str) -> str:
        """Run the configured transformation pipeline.

        Args:
            text: Raw input text.

        Returns:
            Normalized text.
        """
        result = text

        if self._normalize_unicode:
            result = nfc_normalize(result)

        if self._strip_invisible:
            result = strip_invisible(result)

        if self._strip_control:
            result = strip_control(result)

        return result

    @staticmethod
    def decode_and_normalize(
        raw: bytes,
        normalize: bool = True,
        strip_invisible: bool = True,
        strip_control: bool = True,
    ) -> str:
        """Decode bytes then normalize in one call.

        Args:
            raw: Raw bytes (e.g. from file or network).
            normalize: Apply NFC normalization.
            strip_invisible: Remove invisible chars.
            strip_control: Remove control chars.

        Returns:
            Decoded and normalized string.
        """
        try:
            text = _decode_bytes(raw)
        except Exception as exc:
            raise NormalizationError(f"Decoding failed: {exc}") from exc

        if normalize:
            text = nfc_normalize(text)
        if strip_invisible:
            text = strip_invisible(text)
        if strip_control:
            text = strip_control(text)

        return text
