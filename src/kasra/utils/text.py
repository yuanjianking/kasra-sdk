"""Kasra L3 Rule Engine — Text processing utilities.

Shared helpers for Unicode normalization, invisible-character stripping,
boundary-aware truncation, and other cross-module string operations.
"""

from __future__ import annotations

import unicodedata

# Zero-width and otherwise-invisible Unicode codepoints
# that are commonly used for obfuscation / homoglyph attacks.
_INVISIBLE_CHARS: set[str] = {
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "‎",  # LEFT-TO-RIGHT MARK
    "‏",  # RIGHT-TO-LEFT MARK
    "⁠",  # WORD JOINER
    "⁡",  # FUNCTION APPLICATION
    "⁢",  # INVISIBLE TIMES
    "⁣",  # INVISIBLE SEPARATOR
    "⁤",  # INVISIBLE PLUS
    "⁦",  # LEFT-TO-RIGHT ISOLATE
    "⁧",  # RIGHT-TO-LEFT ISOLATE
    "⁨",  # FIRST STRONG ISOLATE
    "⁩",  # POP DIRECTIONAL ISOLATE
    "⁪",  # INHIBIT SYMMETRIC SWAPPING
    "⁫",  # ACTIVATE SYMMETRIC SWAPPING
    "⁬",  # INHIBIT ARABIC FORM SHAPING
    "⁭",  # ACTIVATE ARABIC FORM SHAPING
    "⁮",  # NATIONAL DIGIT SHAPES
    "⁯",  # NOMINAL DIGIT SHAPES
    "﻿",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "­",  # SOFT HYPHEN
    "͏",  # COMBINING GRAPHEME JOINER
    "؜",  # ARABIC LETTER MARK
    "ᅟ",  # HANGUL CHOSEONG FILLER
    "ᅠ",  # HANGUL JUNGSEONG FILLER
    "឴",  # KHMER VOWEL INHERENT AQ
    "឵",  # KHMER VOWEL INHERENT AA
    "᠎",  # MONGOLIAN VOWEL SEPARATOR
    "ㅤ",  # HANGUL FILLER
    "ﾠ",  # HALFWIDTH HANGUL FILLER
}


def strip_invisible(text: str) -> str:
    """Remove invisible Unicode codepoints from *text*."""
    return "".join(ch for ch in text if ch not in _INVISIBLE_CHARS)


def strip_control(text: str, keep_newlines: bool = True) -> str:
    """Strip control characters (Cc, Cf categories) from *text*.

    By default preserves ``\\n``, ``\\t``, and ``\\r``.
    """
    chars: list[str] = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith("Cc") or cat.startswith("Cf"):
            if keep_newlines and ch in ("\n", "\t", "\r"):
                chars.append(ch)
            continue
        chars.append(ch)
    return "".join(chars)


def nfc_normalize(text: str, form: str = "NFC") -> str:
    """Normalize *text* to the specified Unicode form.

    Args:
        text: Input string.
        form: Unicode normalization form (``"NFC"``, ``"NFKC"``, ``"NFD"``, ``"NFKD"``).

    Returns:
        Normalized text.
    """
    return unicodedata.normalize(form.upper(), text)


def normalize_text(text: str, keep_newlines: bool = True, form: str = "NFC") -> str:
    """Full text normalization: Unicode → strip invisible → strip control codes.

    Args:
        text: Input string.
        keep_newlines: Preserve ``\\n``, ``\\t``, ``\\r`` when stripping control chars.
        form: Unicode normalization form (``"NFC"`` or ``"NFKC"``).

    Returns:
        Normalized text.
    """
    text = nfc_normalize(text, form=form)
    text = strip_invisible(text)
    text = strip_control(text, keep_newlines=keep_newlines)
    return text


def truncate_at_boundary(
    text: str,
    max_length: int,
    boundary_lookback: int = 200,
    ellipsis: str = "\n\n<<TRUNCATED>>",
) -> tuple[str, bool]:
    """Truncate *text* at a natural line boundary near *max_length*.

    Returns ``(truncated_text, was_truncated)``.
    """
    if len(text) <= max_length:
        return text, False

    cut = max_length
    # Search backwards from max_length for a newline
    for offset in range(boundary_lookback):
        pos = max_length - offset
        if 0 <= pos < len(text) and text[pos] == "\n":
            cut = pos + 1
            break
    if cut == max_length:
        # Search forward from max_length
        for offset in range(boundary_lookback):
            pos = max_length + offset
            if 0 <= pos < len(text) and text[pos] == "\n":
                cut = pos
                break

    return text[:cut].rstrip() + ellipsis, True
