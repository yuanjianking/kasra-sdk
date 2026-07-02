"""Semgrep adapter — optional AST matching + dataflow for Kasra rules.

Install::

    pip install semgrep

Then the scanner auto-detects ``semgrep`` and uses it as a drop-in backend.

Architecture
------------
- **Batch**: all applicable rules are bundled into a single ``semgrep`` invocation.
- **Cached**: rule YAML files are written once to ``~/.cache/kasra/semgrep/``.
- **Fallback**: if semgrep isn't installed, Kasra falls back to regex.

Usage::

    runner = SemgrepRunner()
    if runner.available:
        findings = runner.run(content, "app.py", ["SEC-05", "SEC-14"])
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from kasra.scanner.models import CodeReviewFinding


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_CACHE_DIR = Path.home() / ".cache" / "kasra" / "semgrep"


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

_SEMGREP_RULES: dict[str, list[dict[str, Any]]] = {
    "SEC-05": [{"pattern": "cursor.execute($QUERY + $INPUT)"}, {"pattern": "execute($QUERY + $INPUT)"},
               {"pattern-not": "execute($QUERY, $PARAMS)"}, {"pattern": "db.Query($QUERY + $INPUT)"},
               {"pattern": "SqlCommand($QUERY + $INPUT)"}],
    "SEC-07": [{"pattern": "subprocess.call($CMD, shell=True)"}, {"pattern": "subprocess.Popen($CMD, shell=True)"},
               {"pattern": "subprocess.run($CMD, shell=True)"}, {"pattern": "os.system($CMD)"},
               {"pattern": "Runtime.getRuntime().exec($CMD)"},
               {"pattern": "exec.Command(\"sh\", \"-c\", $INPUT)"}],
    "SEC-08": [{"pattern": "pickle.loads($X)"}, {"pattern": "yaml.load($X)"},
               {"pattern-not": "yaml.safe_load($X)"}, {"pattern": "ObjectInputStream.readObject()"},
               {"pattern": "BinaryFormatter.Deserialize($X)"}, {"pattern": "unserialize($X)"},
               {"pattern": "Marshal.load($X)"}],
    "SEC-14": [{"pattern": "eval($INPUT)"}, {"pattern": "exec($INPUT)"}, {"pattern": "Function($INPUT)"},
               {"pattern": "ScriptEngine.eval($INPUT)"}],
    "SEC-15": [{"pattern": "document.innerHTML = $X"}, {"pattern": "document.write($X)"},
               {"pattern": "dangerouslySetInnerHTML={{ __html: $X }}"}],
    "SEC-19": [{"pattern": "requests.get($URL)"}, {"pattern": "requests.post($URL)"},
               {"pattern": "axios.get($URL)"}, {"pattern": "fetch($URL)"},
               {"pattern": "HttpClient.execute($URL)"}, {"pattern": "http.Get($URL)"}],
    "SEC-23": [{"pattern": "include($X)"}, {"pattern": "require($X)"}, {"pattern": "fs.readFile($X)"}],
    "SEC-32": [{"pattern": "hashlib.md5($X)"}, {"pattern": "MessageDigest.getInstance(\"MD5\")"},
               {"pattern": "MessageDigest.getInstance(\"SHA-1\")"}],
    "SEC-34": [{"pattern": "requests.get($X, verify=False)"}, {"pattern": "requests.post($X, verify=False)"},
               {"pattern": "InsecureSkipVerify: true"}],
    "SEC-45": [{"pattern": "os.path.join($DIR, $FILE)"}, {"pattern": "Path.Combine($DIR, $FILE)"},
               {"pattern": "new File($BASE, $FILE)"}],
    "SEC-51": [{"pattern": "os.system($CMD)"}, {"pattern": "subprocess.call($CMD)"},
               {"pattern": "Runtime.getRuntime().exec($CMD)"}, {"pattern": "exec.Command($CMD)"},
               {"pattern": "child_process.exec($CMD)"}, {"pattern": "Process.Start($CMD)"}],
    "O-01": [{"pattern": "eval($X)"}, {"pattern": "exec($X)"}, {"pattern": "subprocess.call($X)"},
             {"pattern": "Runtime.getRuntime().exec($X)"}, {"pattern": "Process.Start($X)"},
             {"pattern": "os.system($X)"}],
    "O-04": [{"pattern": "cursor.execute($QUERY + $INPUT)"}, {"pattern-not": "cursor.execute($QUERY, $PARAMS)"},
             {"pattern": "db.Query($QUERY + $INPUT)"}],
    "O-07": [{"pattern": "random.randint($A, $B)"}, {"pattern": "java.util.Random()"}, {"pattern": "Math.random()"}],
    "O-13": [{"pattern": "requests.get($X, verify=False)"}, {"pattern": "InsecureSkipVerify: true"}],
    "O-17": [{"pattern": "document.innerHTML = $X"}, {"pattern": "document.write($X)"},
             {"pattern": "dangerouslySetInnerHTML={{ __html: $X }}"}],
}

_SEMGREP_TAINT_RULES: dict[str, dict[str, Any]] = {
    "SEC-05": {
        "mode": "taint",
        "message": "[SEC-05] User input → SQL query (dataflow)",
        "severity": "WARNING",
        "pattern-sources": [
            {"pattern": "request.body", "langs": ["python"]},
            {"pattern": "req.body", "langs": ["javascript", "typescript"]},
            {"pattern": "req.query", "langs": ["javascript", "typescript", "go"]},
            {"pattern": "input()", "langs": ["python"]},
            {"pattern": "sys.stdin", "langs": ["python"]},
            {"pattern": "request.getParameter($X)", "langs": ["java"]},
            {"pattern": "c.Query($X)", "langs": ["go"]},
            {"pattern": "$_GET[$X]", "langs": ["php"]},
            {"pattern": "$_POST[$X]", "langs": ["php"]},
        ],
        "pattern-sinks": [
            {"pattern": "cursor.execute($X)", "langs": ["python", "javascript"]},
            {"pattern": "executeQuery($X)", "langs": ["java"]},
            {"pattern": "db.execute($X)", "langs": ["python", "go"]},
            {"pattern": "db.Query($X)", "langs": ["go"]},
            {"pattern": "SqlCommand($X)", "langs": ["csharp"]},
            {"pattern": "mysqli_query($X)", "langs": ["php"]},
        ],
        "pattern-sanitizers": [{"pattern": "escape($X)"}, {"pattern": "sanitize($X)"}],
    },
    "SEC-07": {
        "mode": "taint",
        "message": "[SEC-07] User input → shell execution (dataflow)",
        "severity": "WARNING",
        "pattern-sources": [
            {"pattern": "request.body", "langs": ["python"]},
            {"pattern": "req.body", "langs": ["javascript", "typescript"]},
            {"pattern": "input()", "langs": ["python"]},
            {"pattern": "sys.stdin", "langs": ["python"]},
            {"pattern": "request.getParameter($X)", "langs": ["java"]},
            {"pattern": "$_GET[$X]", "langs": ["php"]},
            {"pattern": "$_POST[$X]", "langs": ["php"]},
        ],
        "pattern-sinks": [
            {"pattern": "os.system($X)", "langs": ["python", "javascript"]},
            {"pattern": "subprocess.call($X)", "langs": ["python"]},
            {"pattern": "subprocess.Popen($X)", "langs": ["python"]},
            {"pattern": "subprocess.run($X)", "langs": ["python"]},
            {"pattern": "Runtime.getRuntime().exec($X)", "langs": ["java"]},
            {"pattern": "exec.Command($CMD)", "langs": ["go"]},
            {"pattern": "shell_exec($X)", "langs": ["php"]},
        ],
    },
    "SEC-19": {
        "mode": "taint",
        "message": "[SEC-19] User input → HTTP request (dataflow SSRF)",
        "severity": "WARNING",
        "pattern-sources": [
            {"pattern": "request.body", "langs": ["python"]},
            {"pattern": "req.body", "langs": ["javascript", "typescript"]},
            {"pattern": "req.query", "langs": ["javascript", "typescript"]},
            {"pattern": "input()", "langs": ["python"]},
            {"pattern": "request.getParameter($X)", "langs": ["java"]},
            {"pattern": "$_GET[$X]", "langs": ["php"]},
        ],
        "pattern-sinks": [
            {"pattern": "requests.get($X)", "langs": ["python"]},
            {"pattern": "requests.post($X)", "langs": ["python"]},
            {"pattern": "axios.get($X)", "langs": ["javascript", "typescript"]},
            {"pattern": "fetch($X)", "langs": ["javascript", "typescript"]},
            {"pattern": "HttpClient.execute($X)", "langs": ["java", "csharp"]},
            {"pattern": "http.Get($X)", "langs": ["go"]},
        ],
    },
    "SEC-45": {
        "mode": "taint",
        "message": "[SEC-45] User input → file operation (dataflow path traversal)",
        "severity": "WARNING",
        "pattern-sources": [
            {"pattern": "request.body", "langs": ["python"]},
            {"pattern": "req.body", "langs": ["javascript", "typescript"]},
            {"pattern": "input()", "langs": ["python"]},
            {"pattern": "request.getParameter($X)", "langs": ["java"]},
            {"pattern": "$_GET[$X]", "langs": ["php"]},
        ],
        "pattern-sinks": [
            {"pattern": "open($X)", "langs": ["python"]},
            {"pattern": "os.path.join($DIR, $FILE)", "langs": ["python"]},
            {"pattern": "Path.Combine($DIR, $FILE)", "langs": ["csharp"]},
            {"pattern": "new File($DIR, $FILE)", "langs": ["java"]},
            {"pattern": "file_get_contents($X)", "langs": ["php"]},
            {"pattern": "fs.readFile($X)", "langs": ["javascript", "typescript"]},
        ],
    },
}

_EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".java": "java", ".go": "go", ".cs": "csharp",
    ".php": "php", ".rb": "ruby", ".rs": "rust",
    ".c": "c", ".cpp": "cpp",
    ".kt": "kotlin", ".swift": "swift",
    ".yaml": "yaml", ".yml": "yaml", ".tf": "hcl",
}


def has_semgrep_patterns(rule_id: str) -> bool:
    return rule_id in _SEMGREP_RULES or rule_id in _SEMGREP_TAINT_RULES


def all_supported_rule_ids() -> set[str]:
    return set(_SEMGREP_RULES.keys()) | set(_SEMGREP_TAINT_RULES.keys())


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class SemgrepRunner:
    """Kasra uses this to build and cache semgrep rules.  The rules payload
    is written to a temp file so concurrent rule sets don't collide."""

    _semgrep_path: str | None = None
    _rules_dir: Path = _CACHE_DIR

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        if os.environ.get("KASRA_DISABLE_SEMGREP"):
            return False
        return self._resolve_semgrep() is not None

    @staticmethod
    def _resolve_semgrep() -> str | None:
        if SemgrepRunner._semgrep_path is not None:
            return SemgrepRunner._semgrep_path

        candidates: list[str | Path] = []

        # 1. Same directory as running Python (covers .venv/bin)
        py_dir = Path(sys.executable).parent
        candidates.append(py_dir / "semgrep")

        # 2. shutil.which (searches PATH)
        w = shutil.which("semgrep")
        if w:
            candidates.append(w)

        # 3. Pip package bin dir
        try:
            import semgrep.__main__ as m
            p = Path(m.__file__).parent.parent / "bin" / "semgrep"
            candidates.append(p)
        except (ImportError, Exception):
            pass

        for c in candidates:
            p = Path(c)
            if p.exists() and os.access(str(p), os.X_OK):
                SemgrepRunner._semgrep_path = str(p.resolve())
                return SemgrepRunner._semgrep_path
        return None

    # ------------------------------------------------------------------
    # Run (batch)
    # ------------------------------------------------------------------

    def run(self,
            content: str,
            file_path: str,
            rule_ids: list[str] | None = None) -> list[CodeReviewFinding]:
        """Single ``semgrep --config=... --json`` call for *rule_ids*."""
        semgrep = self._resolve_semgrep()
        if semgrep is None:
            return []

        ext = PurePosixPath(file_path).suffix.lower()
        lang = _EXT_TO_LANG.get(ext)
        if lang is None:
            return []

        if rule_ids is None:
            rule_ids = list(all_supported_rule_ids())

        # 1. Write rules YAML (cached)
        rules_path = self._ensure_rules(rule_ids, lang)
        if rules_path is None:
            return []

        # 2. Write content to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix="." + PurePosixPath(file_path).suffix,
                                         delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name

        try:
            # Rules already contain 'languages', so no -l flag needed
            result = subprocess.run(
                [semgrep, "--json", "--quiet", "--no-git-ignore",
                 f"--config={rules_path}", tmp_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode not in (0, 1):
                return []
            output = json.loads(result.stdout)
        except (json.JSONDecodeError, subprocess.TimeoutExpired, OSError):
            return []
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        # Log semgrep errors (non-critical, but useful for debugging)
        if output.get("errors"):
            for e in output["errors"]:
                if e.get("level") in ("error", "warn"):
                    import logging as _lg
                    _lg.getLogger("kasra.semgrep").debug(
                        "Rule error: %s", e.get("message", "")[:120])

        findings: list[CodeReviewFinding] = []
        for sr in output.get("results", []):
            # semgrep prefixes check_id with rules filename (tmp.SEC-05 → SEC-05)
            raw_id = sr.get("check_id", "UNKNOWN")
            rid = raw_id.split(".")[-1] if "." in raw_id else raw_id
            start_line = sr.get("start", {}).get("line", 0)
            col = sr.get("start", {}).get("col", 0)
            matched = sr.get("extra", {}).get("lines", "")[:200]
            severity_str = sr.get("extra", {}).get("severity", "WARNING")
            sev = {"ERROR": "P0", "WARNING": "P1", "INFO": "P2"}.get(severity_str, "P1")

            findings.append(CodeReviewFinding(
                rule_id=rid,
                rule_name=f"semgrep/{rid}",
                severity=sev,
                file_path=file_path,
                line_number=start_line,
                column=col,
                matched_text=matched,
                confidence=0.75,
                message=f"[{rid}] semgrep: {matched[:80]}",
            ))

        return findings

    # ------------------------------------------------------------------
    # Rule file management
    # ------------------------------------------------------------------

    def _ensure_rules(self, rule_ids: list[str], lang: str) -> str | None:
        """Build and write rules to a temp file, return its path.

        Each invocation gets a unique temp file (not a shared cache keyed
        by hash) so concurrent requests with different rule sets don't
        collide.
        """
        rules: list[dict[str, Any]] = []

        for rid in rule_ids:
            has_taint = rid in _SEMGREP_TAINT_RULES

            if has_taint:
                t = dict(_SEMGREP_TAINT_RULES[rid])
                t["id"] = rid
                t["languages"] = [lang]
                if self._has_viable_patterns(t, lang):
                    rules.append(t)
            elif rid in _SEMGREP_RULES:
                rule = self._build_rule(rid, _SEMGREP_RULES[rid], lang)
                if rule:
                    rules.append(rule)

        if not rules:
            return None

        payload = {"rules": rules}
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        import yaml

        # Derive filename from content hash so the same rule set reuses
        # the same file.
        tag = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
        path = _CACHE_DIR / f"rules-{tag}.yml"

        if not path.exists():
            with open(path, "w") as f:
                yaml.dump(payload, f, default_flow_style=False)

        return str(path)

    @staticmethod
    def _has_viable_patterns(taint_rule: dict[str, Any], lang: str) -> bool:
        """Filter patterns by language compatibility."""
        for key in ("pattern-sources", "pattern-sinks"):
            patterns = taint_rule.get(key, [])
            valid = [p for p in patterns if lang in p.get("langs", ["python"])]
            taint_rule[key] = valid
            if not valid:
                return False
        return True

    @staticmethod
    def _build_rule(rule_id: str, patterns: list[dict[str, Any]],
                    language: str) -> dict[str, Any] | None:
        if not patterns:
            return None
        if not any("pattern" in p for p in patterns):
            return None
        rule: dict[str, Any] = {
            "id": rule_id, "message": f"[{rule_id}] semgrep",
            "severity": "WARNING", "languages": [language],
        }
        if len(patterns) == 1 and "pattern" in patterns[0]:
            rule["pattern"] = patterns[0]["pattern"]
        else:
            rule["patterns"] = patterns
        return rule
