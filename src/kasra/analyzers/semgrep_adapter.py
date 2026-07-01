"""Semgrep adapter — optional AST-level matching backend for code review.

Kasra can use Semgrep (https://semgrep.dev) instead of regex for rules that
need AST-level pattern matching.  This gives:

  - **No false positives inside comments/strings** — Semgrep sees the AST.
  - **Data-flow aware** — ``pattern-sources`` / ``pattern-sinks``.
  - **Multi-line matching** — native, not fragile regex hacks.
  - **Language-accurate** — knows Python's grammar, Java's grammar, etc.

Usage
-----
Semgrep is an **optional** dependency.  If ``semgrep`` is on ``$PATH`` at
scan time it will be used; otherwise Kasra falls back to regex.

  # Install semgrep (one-time)
  pip install semgrep

  # Scanner auto-detects and uses it — no code changes needed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from kasra.scanner.models import CodeReviewFinding

# ---------------------------------------------------------------------------
# Rule → Semgrep-pattern mapping
# ---------------------------------------------------------------------------
# Each entry maps a Kasra rule_id to a list of semgrep patterns.
# Patterns use semgrep syntax (actual code with metavariables like $X).
# Keys: "pattern" (match), "pattern-not" (exclude), "pattern-sources" (taint),
#       "pattern-sinks" (taint).
# Languages are inferred from the file extension at scan time.

_SEMGREP_RULES: dict[str, list[dict[str, Any]]] = {
    # ── Injection ──
    "SEC-05": [
        # SQL string concatenation
        {"pattern": "cursor.execute($QUERY + $INPUT)"},
        {"pattern": "execute($QUERY + $INPUT)"},
        {"pattern-not": "execute($QUERY, $PARAMS)"},
        {"pattern": "db.execute($QUERY + $INPUT)"},
        {"pattern": "db.Query($QUERY + $INPUT)"},
        {"pattern": "stmt.execute($QUERY + $INPUT)"},
    ],
    "SEC-07": [
        # OS command injection
        {"pattern": "subprocess.call($CMD, shell=True)"},
        {"pattern": "subprocess.Popen($CMD, shell=True)"},
        {"pattern": "subprocess.run($CMD, shell=True)"},
        {"pattern": "os.system($CMD)"},
        {"pattern": 'Runtime.getRuntime().exec("$CMD" + $INPUT)'},
        {"pattern": "exec.Command(\"sh\", \"-c\", $INPUT)"},
    ],
    "SEC-08": [
        # Unsafe deserialization
        {"pattern": "pickle.loads($X)"},
        {"pattern": "pickle.load($X)"},
        {"pattern": "yaml.load($X)"},
        {"pattern-not": "yaml.safe_load($X)"},
        {"pattern-not": "yaml.load($X, Loader=yaml.SafeLoader)"},
        {"pattern": "ObjectInputStream.readObject()"},
        {"pattern": "BinaryFormatter.Deserialize($X)"},
        {"pattern": "unserialize($X)"},
        {"pattern": "Marshal.load($X)"},
    ],
    "SEC-14": [
        # Code injection
        {"pattern": "eval($INPUT)"},
        {"pattern": "exec($INPUT)"},
        {"pattern": "Function($INPUT)"},
        {"pattern": "ScriptEngine.eval($INPUT)"},
    ],
    "SEC-15": [
        # XSS
        {"pattern": "document.innerHTML = $X"},
        {"pattern": "document.outerHTML = $X"},
        {"pattern": "document.write($X)"},
        {"pattern": "dangerouslySetInnerHTML={{ __html: $X }}"},
    ],
    "SEC-19": [
        # SSRF
        {"pattern": "requests.get($URL)"},
        {"pattern": "requests.post($URL)"},
        {"pattern": "axios.get($URL)"},
        {"pattern": "axios.post($URL)"},
        {"pattern": "fetch($URL)"},
        {"pattern": "HttpClient.execute($URL)"},
    ],
    "SEC-23": [
        # File inclusion
        {"pattern": "include($X)"},
        {"pattern": "require($X)"},
        {"pattern": "include_once($X)"},
        {"pattern": "require_once($X)"},
        {"pattern": "fs.readFile($X)"},
    ],
    "SEC-45": [
        # Path traversal
        {"pattern": "os.path.join($DIR, $FILE)"},
        {"pattern": "Path.Combine($DIR, $FILE)"},
        {"pattern": "new File($BASE, $FILE)"},
    ],
    "SEC-51": [
        # Command execution
        {"pattern": "os.system($CMD)"},
        {"pattern": "subprocess.call($CMD)"},
        {"pattern": "subprocess.Popen($CMD)"},
        {"pattern": "subprocess.run($CMD)"},
        {"pattern": "Runtime.getRuntime().exec($CMD)"},
        {"pattern": "exec.Command($CMD)"},
        {"pattern": "child_process.exec($CMD)"},
        {"pattern": "child_process.execSync($CMD)"},
        {"pattern": "Process.Start($CMD)"},
        {"pattern": "std::process::Command::new($CMD)"},
    ],
    "SEC-32": [
        # Weak crypto
        {"pattern": "hashlib.md5($X)"},
        {"pattern": "hashlib.sha1($X)"},
        {"pattern": "MessageDigest.getInstance(\"MD5\")"},
        {"pattern": "MessageDigest.getInstance(\"SHA-1\")"},
        {"pattern": "Crypto.Cipher.DES.new($X)"},
    ],
    "SEC-34": [
        # TLS disabled
        {"pattern": "requests.get($X, verify=False)"},
        {"pattern": "requests.post($X, verify=False)"},
        {"pattern": "http.DefaultTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}"},
    ],
    "SEC-48": [
        # Zip slip
        {"pattern": "zipfile.extractall($X)"},
        {"pattern": "tarfile.extractall($X)"},
        {"pattern": "ZipInputStream.getNextEntry()"},
    ],
    "SEC-33": [
        # Insecure random
        {"pattern": "random.randint($A, $B)"},
        {"pattern": "java.util.Random()"},
        {"pattern": "Math.random()"},
    ],
    "SEC-49": [
        # Memory safety
        {"pattern": "gets($BUF)"},
        {"pattern": "strcpy($A, $B)"},
        {"pattern": "sprintf($BUF, $FMT)"},
        {"pattern": "scanf($FMT, $BUF)"},
    ],
    "SEC-50": [
        # Error leak
        {"pattern": 'log.error("...", ex)'},
        {"pattern": 'logging.exception("...")'},
        {"pattern": "traceback.format_exc()"},
        {"pattern": "err.stack"},
    ],
    "SEC-52": [
        # Log injection
        {"pattern": 'logging.info("..." + $INPUT)'},
        {"pattern": 'logger.info("..." + $INPUT)'},
    ],
    "SEC-53": [
        # Integer overflow
        {"pattern": "$BALANCE -= $AMOUNT"},
        {"pattern": "$TOTAL *= $MULTIPLIER"},
    ],
    # ── O-series (AI output detection) ──
    "O-01": [
        {"pattern": "eval($X)"},
        {"pattern": "exec($X)"},
        {"pattern": "subprocess.call($X)"},
        {"pattern": "subprocess.Popen($X)"},
        {"pattern": "subprocess.run($X)"},
        {"pattern": "Runtime.getRuntime().exec($X)"},
        {"pattern": "Process.Start($X)"},
        {"pattern": "os.system($X)"},
    ],
    "O-04": [
        {"pattern": "cursor.execute($QUERY + $INPUT)"},
        {"pattern": "stmt.executeQuery($QUERY + $INPUT)"},
        {"pattern": "db.Query($QUERY + $INPUT)"},
        {"pattern-not": "cursor.execute($QUERY, $PARAMS)"},
    ],
    "O-07": [
        {"pattern": "random.randint($A, $B)"},
        {"pattern": "java.util.Random()"},
        {"pattern": "Math.random()"},
    ],
    "O-13": [
        {"pattern": "requests.get($X, verify=False)"},
        {"pattern": "http.DefaultTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}"},
    ],
    "O-17": [
        {"pattern": "document.innerHTML = $X"},
        {"pattern": "document.write($X)"},
        {"pattern": "dangerouslySetInnerHTML={{ __html: $X }}"},
    ],
}

# Language inference: extension → semgrep language name
_EXT_TO_LANG = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".kt": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".tf": "hcl",
    ".tfvars": "hcl",
    "": "python",
}


def _ext_to_lang(file_path: str) -> str | None:
    """Return the Semgrep language for *file_path*, or ``None``."""
    ext = PurePosixPath(file_path).suffix.lower()
    lang = _EXT_TO_LANG.get(ext)
    if lang:
        return lang
    # Dockerfile
    if PurePosixPath(file_path).name.lower().startswith("dockerfile"):
        return "dockerfile"
    return None


def is_available() -> bool:
    """Check if ``semgrep`` CLI is on ``$PATH``."""
    return shutil.which("semgrep") is not None


def has_semgrep_patterns(rule_id: str) -> bool:
    """Check if *rule_id* has semgrep patterns defined."""
    return rule_id in _SEMGREP_RULES


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

class SemgrepRunner:
    """Runs semgrep on files and maps findings back to Kasra's data model.

    Usage::

        runner = SemgrepRunner()
        if runner.available:
            findings = runner.run(file_path, content, "SEC-05")
    """

    @property
    def available(self) -> bool:
        return is_available()

    def run(self, file_path: str, content: str, rule_id: str) -> list[CodeReviewFinding]:
        """Run a single Kasra rule's semgrep patterns against *content*.

        Returns:
            List of ``CodeReviewFinding`` (empty if no matches or semgrep unavailable).
        """
        if not self.available:
            return []

        patterns = _SEMGREP_RULES.get(rule_id)
        if not patterns:
            return []

        lang = _ext_to_lang(file_path)
        if not lang:
            return []

        # Build a temporary semgrep YAML rule file
        semgrep_rules = self._build_rules(rule_id, patterns, lang)
        if not semgrep_rules:
            return []

        # Write content to a temp file, run semgrep, parse results
        with tempfile.NamedTemporaryFile(mode="w", suffix=".tmp", delete=False, encoding="utf-8") as f:
            f.write(content)
            tmp_path = f.name

        try:
            return self._run_semgrep(tmp_path, semgrep_rules, rule_id, file_path)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_rules(rule_id: str,
                     patterns: list[dict[str, Any]],
                     language: str) -> list[dict[str, Any]] | None:
        """Build semgrep YAML rule dict from pattern list."""
        if not patterns:
            return None

        # Check that at least one "pattern" key exists
        has_pattern = any("pattern" in p for p in patterns)
        if not has_pattern:
            return None

        # Build the rule
        rule: dict[str, Any] = {
            "id": rule_id,
            "message": f"[{rule_id}] matched by semgrep",
            "severity": "WARNING",
            "languages": [language],
        }

        # If there's only one pattern, use it directly
        if len(patterns) == 1 and "pattern" in patterns[0]:
            rule["pattern"] = patterns[0]["pattern"]
        else:
            # Use patterns/pattern-not
            rule["patterns"] = patterns

        return [{"rules": [rule]}]

    @staticmethod
    def _run_semgrep(target_path: str,
                     rules: list[dict[str, Any]],
                     rule_id: str,
                     original_path: str) -> list[CodeReviewFinding]:
        """Call ``semgrep`` CLI and parse JSON output."""
        # Write rules to temp YAML
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False, encoding="utf-8") as f:
            # Use pyyaml to dump clean YAML
            import yaml
            yaml.dump_all(rules, f, default_flow_style=False)
            rules_path = f.name

        try:
            result = subprocess.run(
                ["semgrep", "--json", "--quiet", f"--config={rules_path}", target_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode not in (0, 1):
                return []

            output = json.loads(result.stdout)
        except (json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError):
            return []
        finally:
            try:
                os.unlink(rules_path)
            except OSError:
                pass

        findings: list[CodeReviewFinding] = []
        for semgrep_result in output.get("results", []):
            start_line = semgrep_result.get("start", {}).get("line", 0)
            col = semgrep_result.get("start", {}).get("col", 0)
            matched = semgrep_result.get("extra", {}).get("lines", "")[:200]
            confidence = 0.75  # Semgrep AST matching is more reliable than regex

            findings.append(CodeReviewFinding(
                rule_id=rule_id,
                rule_name=semgrep_result.get("check_id", rule_id),
                severity=semgrep_result.get("extra", {}).get("severity", "WARNING"),
                file_path=original_path,
                line_number=start_line,
                column=col,
                matched_text=matched,
                confidence=confidence,
                message=f"[{rule_id}] {matched[:80]}",
            ))

        return findings
