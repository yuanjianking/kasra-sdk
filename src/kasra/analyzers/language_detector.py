"""Kasra L3 Rule Engine — Language detection analyzer.

Detects the programming language of AI-generated code using deterministic
heuristics (no ML dependency).  Supports 15+ languages commonly generated
by LLMs.

Detection priority (highest confidence first):
  1. Shebang line (``#!/usr/bin/python``)
  2. Unique function calls / APIs (``subprocess.run`` → Python)
  3. Unique import / require statements
  4. Comment syntax patterns
  5. Keyword-based heuristics (``fn main()`` → Rust)
"""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import ClassVar

from kasra.analyzers.base import Analyzer
from kasra.analyzers.context import AnalysisContext, CodeBlock, LanguageResult


# ---------------------------------------------------------------------------
# Language signature definitions
# ---------------------------------------------------------------------------

class _LangSig:
    """Language signature used by the heuristic detector."""

    __slots__ = ("name", "shebangs", "keywords", "imports", "calls", "comment_pattern", "unique_patterns", "weight")

    def __init__(  # noqa: PLR0913
        self,
        name: str,
        shebangs: list[str] | None = None,
        keywords: list[str] | None = None,
        imports: list[str] | None = None,
        calls: list[str] | None = None,
        comment_pattern: str | None = None,
        unique_patterns: list[str] | None = None,
        weight: float = 1.0,
    ) -> None:
        self.name = name
        self.shebangs = shebangs or []
        self.keywords = keywords or []
        self.imports = imports or []
        self.calls = calls or []
        self.comment_pattern = comment_pattern
        self.unique_patterns = unique_patterns or []
        self.weight = weight


# Heuristic scores per signal type
_SHEBANG_SCORE = 0.95
_IMPORT_SCORE = 0.85
_CALL_SCORE = 0.80
_KEYWORD_SCORE = 0.65
_COMMENT_SCORE = 0.55
_PATTERN_SCORE = 0.60

_LANGUAGES: list[_LangSig] = [
    _LangSig(
        name="python",
        shebangs=["python", "python3", "python2"],
        imports=[
            "import os", "import sys", "import re",
            "from typing import", "import numpy", "import pandas",
            "import torch", "import tensorflow", "import django",
            "import flask", "import fastapi",
            "import json", "import pytest", "from pathlib",
            "from collections", "from datetime", "from typing",
        ],
        calls=[
            "subprocess.", "os.system(", "os.popen(", "print(",
            "print(f", "len(", "range(", "def ",
            "open(", "with open", "lambda ", "yield ",
        ],
        comment_pattern=r"^\s*#.*$",
        unique_patterns=[
            r"def \w+\s*\(.*\)\s*:", r"class \w+.*:", r"elif\s+",
            r"__name__\s*==\s*['\"]__main__['\"]",
            r"self\.\w+\s*=", r"->\s*\w+:", r"\.format\(",
            r"f['\"].*\{.*\}",
        ],
    ),
    _LangSig(
        name="javascript",
        shebangs=["node"],
        imports=[
            "require(", "import React", "import express",
            "import axios", "module.exports", "exports.",
            "from 'react", 'from "react',
        ],
        calls=[
            "console.log(", "console.error(", "setTimeout(",
            "setInterval(", "fetch(", "Promise.", "async ",
            "await ", "document.", "window.",
            ".addEventListener(", "querySelector(", "getElementById(",
        ],
        comment_pattern=r"^\s*//.*$",
        unique_patterns=[
            r"=>\s*[{(]", r"const\s+\w+\s*=\s*\(?\w*\)?\s*=>",
            r"\.then\(\s*\(?\w+\)?\s*=>", r"function\s*\w*\s*\(",
            r"typeof\s", r"instanceof\s",
            r"document\.\w+", r"window\.\w+",
            r"\$\s*\(",  # jQuery
        ],
    ),
    _LangSig(
        name="php",
        shebangs=["php"],
        imports=[
            "use ", "namespace ",
        ],
        calls=[
            "echo ", "print_r(", "var_dump(",
            "->", "$this->",
            "header(", "session_start(", "json_decode(",
            "json_encode(", "mysqli_", "pdo_",
        ],
        comment_pattern=r"^\s*//.*$|^\s*#.*$",
        unique_patterns=[
            r"<\?php", r"\$\w+\s*=", r"public\s+function",
            r"private\s+\$", r"protected\s+\$",
            r"new\s+\w+\(\)",
            r"__(?:construct|destruct|get|set|call|toString)\s*\(",
            r"\$\w+\s*->\s*\w+",
        ],
        weight=0.85,
    ),
    _LangSig(
        name="typescript",
        shebangs=[],
        imports=[
            "import {", "import type", "from '", 'from "',
            "interface ", "type ", "implements ",
        ],
        calls=[],
        comment_pattern=r"^\s*//.*$",
        unique_patterns=[
            r":\s*(?:string|number|boolean|any|void|never|unknown)\b",
            r"<\w+>", r"as\s+\w+", r"readonly\s",
            r"\binterface\s+\w+\s*\{", r"\btype\s+\w+\s*=",
            r"\bimplements\s+\w+",
        ],
    ),
    _LangSig(
        name="java",
        shebangs=[],
        imports=[
            "import java.", "import org.", "import com.",
            "import jakarta.", "import javax.",
        ],
        calls=[
            "System.out.println(", "System.out.print(",
            "Runtime.getRuntime()", "new ProcessBuilder",
            "StringBuilder", "ArrayList<", "HashMap<",
            ".toString()", ".equals(", ".length()",
        ],
        comment_pattern=r"^\s*//.*$",
        unique_patterns=[
            r"public\s+(?:static\s+)?void\s+\w+\s*\(",
            r"public\s+class\s+\w+", r"private\s+\w+\s+\w+\s*;",
            r"protected\s+\w+", r"@Override", r"@Test",
            r"\bextends\s+\w+", r"\bnew\s+\w+\(\)",
            r"public\s+static\s+void\s+main\s*\(",
            r"\.class\b", r"new\s+String\b",
        ],
        weight=1.2,
    ),
    _LangSig(
        name="go",
        shebangs=[],
        imports=[
            '"fmt"', '"net/http"', '"os"', '"io"',
            '"strings"', '"encoding/json"', '"log"',
            '"time"', '"sync"', '"context"',
        ],
        calls=[
            "fmt.Println(", "fmt.Sprintf(", "fmt.Printf(",
            "http.HandleFunc(", "http.ListenAndServe(",
            "json.Marshal(", "json.Unmarshal(",
            "defer ", "go ",
        ],
        comment_pattern=r"^\s*//.*$",
        unique_patterns=[
            r"func\s+\w+\s*\(.*\).*\{", r"func\s+main\s*\(\)",
            r"package\s+\w+", r"\bif\s+err\s+!=\s+nil\b",
            r"defer\s+\w+", r"go\s+\w+",
            r"var\s+\w+\s+\*?\w+", r":=",
        ],
    ),
    _LangSig(
        name="rust",
        shebangs=[],
        imports=[
            "use ", "use std::", "use tokio::", "use serde::",
            "use crate::", "mod ",
        ],
        calls=[
            "println!(", "format!(",
            ".unwrap()", ".expect(", ".clone()",
            ".as_ref()", ".iter()", ".collect()",
        ],
        comment_pattern=r"^\s*//.*$",
        unique_patterns=[
            r"fn\s+\w+\s*\(.*\)\s*(?:->\s*\w+)?\s*\{",
            r"fn\s+main\s*\(", r"let\s+mut\s+\w+",
            r"let\s+\w+\s*=\s*", r"match\s+\w+\s*\{",
            r"impl\s+\w+", r"#\[", r"unsafe\s*\{",
            r"\.await", r"async\s+fn",
        ],
    ),
    _LangSig(
        name="ruby",
        shebangs=["ruby"],
        imports=[
            "require '", 'require "',
            "gem '", 'gem "',
        ],
        calls=[
            "puts ", "print ", "def ", "class ",
            ".each do", ".map {", ".select {",
            "attr_accessor", "attr_reader",
        ],
        comment_pattern=r"^\s*#.*$",
        unique_patterns=[
            r"def\s+\w+\s*\(.*\)", r"class\s+\w+\s*[<]",
            r"end\b", r"do\s*\|", r"@\w+",
            r"@@\w+", r"attr_\w+", r"has_many",
            r"belongs_to", r"render\s+", r"redirect_to",
        ],
    ),
    _LangSig(
        name="php",
        shebangs=["php"],
        imports=[
            "use ", "namespace ",
        ],
        calls=[
            "echo ", "print_r(", "var_dump(",
            "function ", "$this->", "->",
            "header(", "session_start(", "json_decode(",
            "json_encode(", "mysqli_", "pdo_",
        ],
        comment_pattern=r"^\s*//.*$|^\s*#.*$",
        unique_patterns=[
            r"<\?php", r"\$\w+\s*=", r"public\s+function",
            r"private\s+\$", r"protected\s+\$",
            r"->", r"new\s+\w+\(\)",
            r"__(?:construct|destruct|get|set|call|toString)\s*\(",
        ],
    ),
    _LangSig(
        name="cpp",
        shebangs=[],
        imports=[
            "#include <", "#include \"",
        ],
        calls=[
            "std::", "cout <<", "cin >>",
            "new ", "delete ", "delete[] ",
            ".push_back(", ".begin()", ".end()",
        ],
        comment_pattern=r"^\s*//.*$",
        unique_patterns=[
            r"#include\s", r"int\s+main\s*\(", r"->\s*\w+\s*\(",
            r"template\s*<", r"class\s+\w+\s*[;{]",
            r"virtual\s+", r"override\b", r"const\s+\w+&",
            r"::\s*\w+\s*\(", r"nullptr\b",
        ],
    ),
    _LangSig(
        name="csharp",
        shebangs=[],
        imports=[
            "using System;", "using System.Collections",
            "using System.Linq", "using Microsoft.",
            "using Newtonsoft",
        ],
        calls=[
            "Console.WriteLine(", "Console.Write(",
            "var ", "async ", "await ",
            "LINQ", ".Select(", ".Where(",
        ],
        comment_pattern=r"^\s*//.*$",
        unique_patterns=[
            r"namespace\s+\w+", r"class\s+\w+\s*[:\s{]",
            r"string\s+\w+\s*=", r"int\s+\w+\s*=",
            r"bool\s+\w+\s*=", r"var\s+\w+\s*=",
            r"public\s+(?:static\s+)?\w+", r"async\s+Task",
            r"#region", r"get;\s*set;", r"init;\s*set;",
        ],
    ),
    _LangSig(
        name="kotlin",
        shebangs=[],
        imports=[
            "import ", "import kotlin.",
            "import android.", "import androidx.",
        ],
        calls=[
            "println(", "print(",
            "val ", "var ", "fun ",
            ".apply {", ".let {", ".also {",
        ],
        comment_pattern=r"^\s*//.*$",
        unique_patterns=[
            r"fun\s+\w+\s*\(", r"val\s+\w+\s*[=:]",
            r"var\s+\w+\s*[=:]", r"data\s+class",
            r"sealed\s+class", r"object\s+\w+",
            r"companion\s+object", r"override\s+fun",
            r":\s*(?:String|Int|Boolean|List<|Map<)",
        ],
    ),
    _LangSig(
        name="swift",
        shebangs=[],
        imports=[
            "import UIKit", "import Foundation",
            "import SwiftUI", "import Combine",
        ],
        calls=[
            "print(", "NSLog(",
            ".map {", ".filter {", ".reduce(",
        ],
        comment_pattern=r"^\s*//.*$",
        unique_patterns=[
            r"func\s+\w+\s*\(", r"var\s+\w+\s*[=:]",
            r"let\s+\w+\s*[=:]", r"struct\s+\w+",
            r"class\s+\w+\s*[:\s{]", r"guard\s+",
            r"defer\s+\{", r"weak\s+var",
            r"\@\w+", r"->\s*\w+",
        ],
    ),
    _LangSig(
        name="bash",
        shebangs=["bash", "sh", "zsh", "dash"],
        imports=[],
        calls=[
            "echo ", "export ", "source ",
            "if ", "then", "fi", "esac",
            "case ", "while ", "for ",
        ],
        comment_pattern=r"^\s*#.*$",
        unique_patterns=[
            r"#!/", r"\$\{?\w+\}?", r"\$\(.*\)",
            r"`[^`]+`", r"\bif\s+\[", r"\bfi\b",
            r"\besac\b", r"\bdo\b", r"\bdone\b",
            r"\bexit\s+\d+\b",
        ],
    ),
    _LangSig(
        name="powershell",
        shebangs=[],
        imports=[],
        calls=[
            "Write-Host ", "Write-Output ", "Get-",
            "Set-", "New-", "Remove-",
        ],
        comment_pattern=r"^\s*#.*$",
        unique_patterns=[
            r"\$\w+", r"Get-\w+", r"Set-\w+",
            r"New-\w+", r"Remove-\w+", r"Write-\w+",
            r"Param\s*\(", r"\[Parameter", r"[CmdletBinding",
            r"foreach\s*\(.*\$", r"if\s*\(.*\$",
        ],
    ),
    _LangSig(
        name="sql",
        shebangs=[],
        imports=[],
        calls=[
            "SELECT ", "FROM ", "WHERE ", "INSERT INTO",
            "UPDATE ", "DELETE ", "CREATE TABLE",
            "ALTER TABLE", "DROP TABLE", "JOIN ",
            "GROUP BY", "ORDER BY", "HAVING ",
        ],
        comment_pattern=r"^\s*--.*$",
        unique_patterns=[
            r"\bSELECT\b.*\bFROM\b", r"\bINSERT\s+INTO\b",
            r"\bUPDATE\b.*\bSET\b", r"\bDELETE\b.*\bFROM\b",
            r"\bJOIN\b.*\bON\b", r"'.*'", r"\bNULL\b",
            r"\bDISTINCT\b", r"\bAS\b",
        ],
    ),
]


# ---------------------------------------------------------------------------
# Analyzer implementation
# ---------------------------------------------------------------------------

class LanguageDetector(Analyzer):
    """Detect the programming language in content using deterministic heuristics.

    Supports 15 languages: python, javascript, typescript, java, go, rust,
    ruby, php, cpp, csharp, kotlin, swift, bash, powershell, sql.

    Results are cached by content hash to avoid re-detection.
    """

    layer: int = 2
    name: str = "language_detector"

    _SHEBANG_RE = re.compile(r"^#!\s*(?:\S*/)?(\w+)", re.MULTILINE)

    _MAX_CACHE_SIZE = 2048

    def __init__(self) -> None:
        super().__init__()
        self._cache: OrderedDict[int, tuple[str | None, float, list[str]]] = OrderedDict()

    def analyze(self, content: str, context: AnalysisContext) -> AnalysisContext:
        """Run language detection and populate *context*."""
        if not content.strip():
            return context

        # Cache key (LRU: touch on hit, evict oldest when full)
        cache_key = hash(content)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._cache.move_to_end(cache_key)
            context.detected_language, context.language_confidence, context.language_evidence = cached
            return context

        result = self._detect(content)
        context.detected_language = result.language
        context.language_confidence = result.confidence
        context.language_evidence = result.evidence

        self._cache[cache_key] = (result.language, result.confidence, result.evidence)
        while len(self._cache) > self._MAX_CACHE_SIZE:
            self._cache.popitem(last=False)
        return context

    def clear_cache(self) -> None:
        """Clear the detection result cache."""
        self._cache.clear()

    # ------------------------------------------------------------------
    # Detection logic
    # ------------------------------------------------------------------

    def _detect(self, content: str) -> LanguageResult:
        """Detect language in *content* using multi-signal heuristic."""
        scores: dict[str, float] = {}
        evidence: dict[str, list[str]] = {}
        lines = content.split("\n")

        # 1. Shebang detection (highest confidence)
        shebang_match = self._SHEBANG_RE.search(content)
        if shebang_match:
            interpreter = shebang_match.group(1)
            for lang in _LANGUAGES:
                if interpreter in lang.shebangs:
                    scores[lang.name] = scores.get(lang.name, 0) + _SHEBANG_SCORE
                    evidence.setdefault(lang.name, []).append(f"shebang: {interpreter}")

        # 2. Import / require / include patterns
        for line in lines[:50]:
            line_stripped = line.strip()
            for lang in _LANGUAGES:
                for imp in lang.imports:
                    if imp in line_stripped:
                        scores[lang.name] = scores.get(lang.name, 0) + _IMPORT_SCORE
                        evidence.setdefault(lang.name, []).append(f"import: {imp}")
                        break  # one match per language per line

        # 3. Unique function calls
        for line in lines[:100]:
            line_stripped = line.strip()
            for lang in _LANGUAGES:
                for call in lang.calls:
                    if call in line_stripped:
                        scores[lang.name] = scores.get(lang.name, 0) + _CALL_SCORE
                        evidence.setdefault(lang.name, []).append(f"call: {call}")
                        break

        # 4. Unique structural patterns (regex)
        for lang in _LANGUAGES:
            if not lang.unique_patterns:
                continue
            pattern_matches = 0
            for pat in lang.unique_patterns:
                try:
                    if re.search(pat, content, re.MULTILINE):
                        pattern_matches += 1
                except re.error:
                    pass
            if pattern_matches > 0:
                score = _PATTERN_SCORE * min(1.0, pattern_matches / 3.0)
                scores[lang.name] = scores.get(lang.name, 0) + score
                evidence.setdefault(lang.name, []).append(f"{pattern_matches} structural patterns matched")

        # 5. Comment style (lower confidence, tiebreaker)
        for lang in _LANGUAGES:
            if lang.comment_pattern:
                try:
                    comment_count = len(re.findall(lang.comment_pattern, content, re.MULTILINE))
                    if comment_count >= 2:
                        scores[lang.name] = scores.get(lang.name, 0) + _COMMENT_SCORE * 0.5
                        evidence.setdefault(lang.name, []).append(f"comment style: {comment_count} matches")
                except re.error:
                    pass

        # Weight by language-specific multiplier
        for lang in _LANGUAGES:
            if lang.name in scores:
                scores[lang.name] *= lang.weight

        if not scores:
            return LanguageResult(language=None, confidence=0.0, evidence=["no language signals detected"])

        # Pick the best candidate
        best_lang = max(scores, key=lambda k: scores[k])
        best_score = scores[best_lang]

        # Normalise confidence to 0.0–1.0
        confidence = min(1.0, best_score / 2.5)

        # Second-best: if scores are very close, confidence drops
        sorted_scores = sorted(scores.values(), reverse=True)
        if len(sorted_scores) > 1 and sorted_scores[1] > sorted_scores[0] * 0.8:
            confidence *= 0.8

        return LanguageResult(
            language=best_lang,
            confidence=round(confidence, 3),
            evidence=evidence.get(best_lang, []),
        )
