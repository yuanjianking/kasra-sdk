"""Kasra L3 Rule Engine — Code block boundary analyzer.

Identifies code block boundaries, fence types, and comment regions
in content so that downstream matchers can determine whether a match
occurred inside or outside a code block.
"""

from __future__ import annotations

import re

from kasra.analyzers.base import Analyzer
from kasra.analyzers.context import AnalysisContext, CodeBlock


class CodeBlockAnalyzer(Analyzer):
    """Identify code block boundaries in content.

    Detects:
    - Fenced code blocks (triple-backtick `` ``` `` or `` ~~~ ``)
    - Indented code blocks (4-space or tab-prefixed lines)
    - Inline code (single-backtick delimited)
    - Comment regions (line and block comments)

    Provides ``is_in_code_block(offset)`` and ``get_code_block_at(offset)``
    helpers for use by downstream matchers.
    """

    layer: int = 2
    name: str = "code_block_analyzer"

    _FENCE_RE = re.compile(r"^(```|~~~)(\w*)\s*$", re.MULTILINE)
    _INLINE_CODE_RE = re.compile(r"`[^`]+`")
    _BLOCK_COMMENT_RE = re.compile(r"/\*[\s\S]*?\*/|<!--[\s\S]*?-->")
    _LINE_COMMENT_RE = re.compile(r"^\s*(#|//|--|%).*$", re.MULTILINE)

    def analyze(self, content: str, context: AnalysisContext) -> AnalysisContext:
        """Parse code blocks from *content* and populate *context*."""
        if not content.strip():
            return context

        blocks: list[CodeBlock] = []
        content_len = len(content)
        lines = content.split("\n")

        # 1. Fenced code blocks
        blocks.extend(self._find_fenced_blocks(content, lines))

        # 2. Block comment regions
        blocks.extend(self._find_block_comments(content, lines))

        # 3. Indented code blocks (supplemental — heuristics only)
        blocks.extend(self._find_indented_blocks(content, lines))

        # Merge overlapping blocks
        merged = self._merge_code_blocks(blocks)

        # Store with unique perms but attach language from fences
        context.code_blocks = merged
        return context

    # ------------------------------------------------------------------
    # Block detection helpers
    # ------------------------------------------------------------------

    def _find_fenced_blocks(self, content: str, lines: list[str]) -> list[CodeBlock]:
        """Detect triple-backtick and tilde fenced code blocks."""
        blocks: list[CodeBlock] = []
        fences: list[tuple[int, str, str]] = []  # (line_idx, lang, fencer)
        char_offset = 0

        for i, line in enumerate(lines):
            m = self._FENCE_RE.match(line)
            if m:
                fencer = m.group(1)  # ``` or ~~~
                lang = m.group(2) or ""
                if fences and fences[-1][2] == fencer and fences[-1][0] != i:
                    # Closing fence
                    start_line, start_lang, _ = fences.pop()
                    start_char = sum(len(l) + 1 for l in lines[:start_line])
                    end_char = sum(len(l) + 1 for l in lines[:i + 1])
                    blocks.append(CodeBlock(
                        language=start_lang or None,
                        start_line=start_line,
                        end_line=i,
                        start_char=start_char,
                        end_char=end_char,
                        content_snippet=content[start_char:start_char + 200].replace("\n", " "),
                        is_comment=False,
                        is_fenced=True,
                    ))
                else:
                    fences.append((i, lang, fencer))
            char_offset += len(line) + 1

        return blocks

    def _find_block_comments(self, content: str, lines: list[str]) -> list[CodeBlock]:
        """Detect ``/* */`` and ``<!-- -->`` block comment regions."""
        blocks: list[CodeBlock] = []
        for m in self._BLOCK_COMMENT_RE.finditer(content):
            start = m.start()
            end = m.end()
            start_line = content[:start].count("\n")
            end_line = start_line + content[start:end].count("\n")
            blocks.append(CodeBlock(
                language=None,
                start_line=start_line,
                end_line=end_line,
                start_char=start,
                end_char=end,
                content_snippet=m.group()[:200].replace("\n", " "),
                is_comment=True,
                is_fenced=False,
            ))
        return blocks

    def _find_indented_blocks(self, content: str, lines: list[str]) -> list[CodeBlock]:
        """Detect indented code blocks (4-space or tab prefix)."""
        blocks: list[CodeBlock] = []
        in_block = False
        block_start = 0
        block_start_line = 0
        char_offset = 0

        for i, line in enumerate(lines):
            is_indented = bool(line) and (line.startswith("    ") or line.startswith("\t"))
            # Skip fences already detected and blank lines within a block
            if not in_block and is_indented:
                in_block = True
                block_start = char_offset
                block_start_line = i
            elif in_block and not is_indented and line.strip():
                # End of indented block
                in_block = False
                end = char_offset
                if block_start < end:
                    blocks.append(CodeBlock(
                        language=None,
                        start_line=block_start_line,
                        end_line=i - 1,
                        start_char=block_start,
                        end_char=end,
                        content_snippet=content[block_start:block_start + 200].replace("\n", " "),
                        is_comment=False,
                        is_fenced=False,
                    ))
            char_offset += len(line) + 1

        # Unclosed block at EOF
        if in_block:
            blocks.append(CodeBlock(
                language=None,
                start_line=block_start_line,
                end_line=len(lines) - 1,
                start_char=block_start,
                end_char=len(content),
                content_snippet=content[block_start:block_start + 200].replace("\n", " "),
                is_comment=False,
                is_fenced=False,
            ))

        return blocks

    # ------------------------------------------------------------------
    # Post-processing
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_code_blocks(blocks: list[CodeBlock]) -> list[CodeBlock]:
        """Merge overlapping / adjacent code blocks."""
        if not blocks:
            return []

        sorted_blocks = sorted(blocks, key=lambda b: b.start_char)
        merged: list[CodeBlock] = [sorted_blocks[0]]

        for b in sorted_blocks[1:]:
            prev = merged[-1]
            # Overlap or adjacency
            if b.start_char <= prev.end_char + 1:
                # Merge — keep the language if fenced provides it
                merged[-1] = CodeBlock(
                    language=prev.language or b.language,
                    start_line=min(prev.start_line, b.start_line),
                    end_line=max(prev.end_line, b.end_line),
                    start_char=prev.start_char,
                    end_char=max(prev.end_char, b.end_char),
                    content_snippet=prev.content_snippet,
                    is_comment=prev.is_comment or b.is_comment,
                    is_fenced=prev.is_fenced or b.is_fenced,
                )
            else:
                merged.append(b)

        return merged

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_in_code_block(offset: int, blocks: list[CodeBlock]) -> bool:
        """Check if character at *offset* is inside any code block."""
        return any(b.start_char <= offset < b.end_char for b in blocks)

    @staticmethod
    def get_code_block_at(offset: int, blocks: list[CodeBlock]) -> CodeBlock | None:
        """Get the code block containing *offset*, or ``None``."""
        for b in blocks:
            if b.start_char <= offset < b.end_char:
                return b
        return None
