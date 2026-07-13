"""Code review scanner — engine for scanning code repositories."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import time
from pathlib import Path, PurePosixPath
from typing import Any

from kasra.scanner.models import CodeReviewFinding, CodeReviewResult
from kasra.scanner.checkers import (
    init_checkers, run_checker,
    match_dockerfile, match_yaml_path, match_keyvalue,
)


# Default patterns to always ignore
IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv",
               ".tox", ".eggs", "eggs", ".mypy_cache", ".ruff_cache",
               ".pytest_cache", ".svn", ".hg", "dist", "build", ".next",
               "target", "bin", "obj", ".terraform", ".serverless"}

IGNORE_EXTS = {".pyc", ".pyo", ".so", ".dll", ".dylib", ".exe",
               ".o", ".a", ".lib", ".obj", ".png", ".jpg", ".jpeg",
               ".gif", ".ico", ".svg", ".ttf", ".woff", ".woff2",
               ".eot", ".mp3", ".mp4", ".wav", ".zip", ".tar", ".gz",
               ".bz2", ".7z", ".rar", ".pdf", ".doc", ".docx",
               ".xls", ".xlsx", ".ppt", ".pptx", ".min.js", ".min.css"}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MiB

KASRAIGNORE_FILENAME = ".kasraignore"


def _load_ignore_patterns(scan_root: Path) -> list[str]:
    """Load patterns from ``.kasraignore`` in *scan_root*.

    Returns:
        List of ``fnmatch`` patterns (empty if no file exists).
    """
    ignore_file = scan_root / KASRAIGNORE_FILENAME
    if not ignore_file.exists():
        return []
    try:
        patterns: list[str] = []
        for line in ignore_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
        return patterns
    except OSError:
        return []


_is_vulnerable_impl = None
def _is_vulnerable(installed: str, vulnerable_range: str) -> bool:
    """Compare semver strings for CVE checking."""
    global _is_vulnerable_impl
    if _is_vulnerable_impl is None:
        from kasra.scanner.checkers import _is_vulnerable as _impl
        _is_vulnerable_impl = _impl
    return _is_vulnerable_impl(installed, vulnerable_range)


def _matches_glob(file_path: str, patterns: list[str]) -> bool:
    """Check if a file path matches any of the glob patterns.

    Supports ``**`` (globstar) via :meth:`pathlib.PurePosixPath.match`.
    Plain filenames (no directory component) also match ``**/*`` patterns.
    """
    if not patterns:
        return True
    norm = file_path.replace(os.sep, "/")
    pp = PurePosixPath(norm)
    for pattern in patterns:
        if pp.match(pattern):
            return True
        # ``**/*`` does not match bare filenames in pathlib: also check
        # against a synthetic parent so ``config.py`` matches ``**/*.py``.
        if "/" not in norm and "/" in pattern:
            prefixed = PurePosixPath("x/" + norm)
            if prefixed.match(pattern):
                return True
    return False


_SEMGREP_AVAILABLE: bool | None = None
_SEMGREP_RUNNER: Any | None = None


def _try_semgrep(content: str, rel_path: str, rule_id: str,
                  matches: list[dict[str, Any]]) -> None:
    """Phase 0: run Semgrep AST matching.

    Semgrep is a **required** dependency for any rule that has Semgrep
    patterns.  If a rule needs Semgrep and it is not available, an
    :exc:`ImportError` is raised.  Rules without Semgrep patterns are
    skipped gracefully.

    Raises:
        ImportError: If a rule requires Semgrep but it is not installed.
        Exception: If semgrep execution fails.
    """
    global _SEMGREP_AVAILABLE, _SEMGREP_RUNNER

    # One-time import of the adapter (in-memory pattern registry — no CLI needed)
    if _SEMGREP_RUNNER is None:
        try:
            from kasra.analyzers.semgrep_adapter import (
                SemgrepRunner as SR,
                has_semgrep_patterns as HSM,
            )
            _SEMGREP_RUNNER = (SR(), HSM)
        except ImportError as exc:
            raise ImportError(
                "Semgrep package is required for code review. "
                "Install it with: pip install kasra-sdk[semgrep]"
            ) from exc

    runner, has_patterns = _SEMGREP_RUNNER
    if not has_patterns(rule_id):
        return  # this rule doesn't use Semgrep — normal

    # This rule needs Semgrep — ensure the CLI is on PATH
    if _SEMGREP_AVAILABLE is None:
        try:
            import subprocess
            result = subprocess.run(["semgrep", "--version"],
                                    capture_output=True, text=True, timeout=5)
            _SEMGREP_AVAILABLE = result.returncode == 0
        except Exception as exc:
            _SEMGREP_AVAILABLE = False
            raise ImportError(
                "Semgrep CLI is required for code review but was not found "
                "on PATH. Install it with: pip install kasra-sdk[semgrep]"
            ) from exc

    if not _SEMGREP_AVAILABLE:
        raise ImportError(
            "Semgrep CLI is required for code review but was not found "
            "on PATH. Install it with: pip install kasra-sdk[semgrep]"
        )

    findings = runner.run(rel_path, content, rule_id)
    seen: set[tuple[int, int]] = set()
    for f in findings:
        pos = (f.line_number, f.column)
        if pos in seen:
            continue
        seen.add(pos)
        matches.append({
            "start": max(0, f.line_number - 1),
            "end": f.line_number,
            "matched": f.matched_text[:200],
            "confidence": f.confidence,
            "pattern": f"semgrep/{rule_id}",
        })


class CodeReviewScanner:
    """Scans code repositories for security vulnerabilities.

    Rules are injected via ``set_rules()`` (typically from the database).
    Walks a target directory and applies detection patterns to matching files.
    """

    def __init__(self, rules_path: str | Path | None = None) -> None:
        self._rules_path: Path | None = Path(rules_path) if rules_path else None

        self._rules: list[dict[str, Any]] = []
        self._custom_rules: list[dict[str, Any]] = []
        self._ignore_patterns: list[str] = []
        self._disabled_rule_ids: set[str] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_rules(self) -> int:
        """Load code review rules from the JSON file (DEPRECATED).

        .. deprecated:: 0.4
           Use ``set_rules()`` to inject rules from an external source
           (e.g. database) instead of reading from disk.

        Returns:
            Number of rules loaded.

        Raises:
            FileNotFoundError: If the rules file does not exist.
            json.JSONDecodeError: If the JSON is invalid.
        """
        path = self._rules_path
        if not path or not path.exists():
            raise FileNotFoundError(f"Code review rules file not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self._rules = data.get("rules", [])
        return len(self._rules)

    @property
    def rules(self) -> list[dict[str, Any]]:
        """Return built-in code review rules only (custom rules excluded).

        Custom rules are stored in ``_custom_rules`` and are included
        during ``scan()`` via ``_rules + _custom_rules``, but they are
        **not** exposed through this property to avoid confusion in API
        listing (custom rules are listed separately from the DB table).
        """
        return list(self._rules)

    @property
    def rule_ids(self) -> list[str]:
        """Return the list of built-in rule IDs only."""
        return [r.get("id", "UNKNOWN") for r in self._rules]

    @property
    def all_rule_ids(self) -> list[str]:
        """Return the list of all rule IDs (built-in + custom).

        Used during ``scan()`` for enable/disable checks.
        """
        return self.rule_ids + [r.get("id", "UNKNOWN") for r in self._custom_rules]

    def set_rules(self, rules: list[dict[str, Any]]) -> None:
        """Replace all built-in code review rules from an external list.

        Use this instead of ``load_rules()`` when rules come from a
        database rather than a JSON file on disk.

        Args:
            rules: A list of code review rule dicts.
        """
        self._rules = list(rules)

    @property
    def disabled_rule_ids(self) -> set[str]:
        """Return the set of currently disabled rule IDs."""
        return set(self._disabled_rule_ids)

    def enable_rule(self, rule_id: str) -> None:
        """Re-enable a code review rule at runtime.

        Args:
            rule_id: The rule ID to enable (e.g. ``"SEC-01"``).

        Raises:
            ValueError: If the rule ID is not found.
        """
        if rule_id not in self.all_rule_ids:
            raise ValueError(f"Code review rule not found: {rule_id}")
        self._disabled_rule_ids.discard(rule_id)

    def disable_rule(self, rule_id: str) -> None:
        """Disable a code review rule at runtime.

        Args:
            rule_id: The rule ID to disable (e.g. ``"SEC-01"``).

        Raises:
            ValueError: If the rule ID is not found.
        """
        if rule_id not in self.all_rule_ids:
            raise ValueError(f"Code review rule not found: {rule_id}")
        self._disabled_rule_ids.add(rule_id)

    # ------------------------------------------------------------------
    # Custom rule management
    # ------------------------------------------------------------------

    def add_custom_rule(self, rule: dict[str, Any]) -> None:
        """Add a custom code review rule at runtime.

        The rule dict uses the same structure as built-in rules:
          ``{ "id": "U-01", "name": "My Rule", "severity": "P1",
               "action": "warn", "target_files": ["**/*.py"],
               "detection": { "patterns": [{"type": "regex", "value": "...",
                                            "confidence": 0.8}] } }``

        Custom rules are included in subsequent ``scan()`` calls.
        If a rule with the same ID already exists it is overwritten.

        Args:
            rule: A rule dict following the code review rule schema.
        """
        # Remove existing custom rule with same ID, then add
        rid = rule.get("id", "")
        self._custom_rules = [r for r in self._custom_rules if r.get("id") != rid]
        self._custom_rules.append(rule)

    def remove_custom_rule(self, rule_id: str) -> bool:
        """Remove a custom code review rule at runtime.

        Args:
            rule_id: The custom rule ID to remove.

        Returns:
            ``True`` if the rule was found and removed, ``False`` otherwise.
        """
        before = len(self._custom_rules)
        self._custom_rules = [r for r in self._custom_rules if r.get("id") != rule_id]
        return len(self._custom_rules) < before

    def scan(self, path: str | Path) -> CodeReviewResult:
        """Scan a file or directory for code review findings.

        Args:
            path: Path to a file or directory to scan.

        Returns:
            A CodeReviewResult containing all findings.
        """
        start = time.monotonic()
        scan_path = Path(path)
        result = CodeReviewResult(scan_path=str(scan_path.resolve()))

        if not scan_path.exists():
            result.error = f"Path does not exist: {scan_path}"
            return result

        if not self._rules:
            result.error = "No rules loaded. Call load_rules() first."
            return result

        # Load .kasraignore patterns
        self._ignore_patterns = (
            _load_ignore_patterns(scan_path)
            if scan_path.is_dir()
            else _load_ignore_patterns(scan_path.parent)
        )

        if scan_path.is_file():
            self._scan_file(scan_path, result)
        else:
            self._scan_directory(scan_path, result)

        result.duration_ms = (time.monotonic() - start) * 1000
        return result

    # ------------------------------------------------------------------
    # Internal: directory walking
    # ------------------------------------------------------------------

    def _scan_directory(self, directory: Path, result: CodeReviewResult) -> None:
        """Walk a directory and scan all matching files."""
        for root, dirs, files in os.walk(directory):
            # Skip ignored directories (modify dirs in-place for os.walk)
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
            # Sort for deterministic order
            dirs.sort()
            files.sort()

            for filename in files:
                filepath = Path(root) / filename
                self._scan_file(filepath, result)

    def _scan_file(self, filepath: Path, result: CodeReviewResult) -> None:
        """Scan a single file against applicable rules."""
        # Skip ignored extensions (but always include Dockerfile/config files)
        if filepath.suffix.lower() in IGNORE_EXTS:
            if filepath.name.lower() != "dockerfile" and not filepath.name.startswith("Dockerfile"):
                result.files_skipped += 1
                return

        # Skip large files
        try:
            if filepath.stat().st_size > MAX_FILE_SIZE:
                result.files_skipped += 1
                return
        except OSError:
            result.files_skipped += 1
            return

        # Try to read as text
        try:
            content = filepath.read_text("utf-8", errors="replace")
        except (UnicodeDecodeError, OSError):
            result.files_skipped += 1
            return

        # Normalize Dockerfile names so they match target_files patterns like "**/Dockerfile"
        if filepath.name.lower() == "dockerfile":
            pass  # PurePath.match handles it

        rel_path: str
        sp = result.scan_path  # type: ignore[has-type]
        if sp:
            try:
                rp = str(filepath.relative_to(sp))
                # When scanning a single file, relative_to returns '.'
                # Instead use the parent directory as base
                if rp == '.':
                    rel_path = filepath.name
                else:
                    rel_path = rp
            except ValueError:
                # Not under scan_path — use just the filename
                rel_path = filepath.name
        else:
            rel_path = str(filepath)
        result.files_scanned += 1

        # Check each rule against this file (built-in + custom)
        for rule in self._rules + self._custom_rules:
            rule_id = rule.get("id", "UNKNOWN")
            if rule_id in self._disabled_rule_ids:
                continue
            target_patterns = rule.get("target_files", ["**/*"])
            if not _matches_glob(rel_path, target_patterns):
                continue

            self._apply_rule(rule, content, rel_path, result)

    # ------------------------------------------------------------------
    # Internal: rule application — dispatches to dedicated Python checkers
    # ------------------------------------------------------------------

    _CODE_CHECKS: dict[str, tuple[str, str, str, str]] = {}  # rule_id -> (check_name, file_types)

    @classmethod
    def _init_code_checks(cls) -> None:
        """Register built-in code-check rules."""
        if cls._CODE_CHECKS:
            return

        # Each rule_id maps to: (method_name, supported_extensions, min_confidence, description)
        checks: dict[str, tuple[str, list[str], float, str]] = {
            # ── Injection ──
            "SEC-05": ("_check_sql_injection", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.65, "SQL injection via string concat"),
            "SEC-07": ("_check_os_command_injection", ["py", "js", "ts", "java", "go", "cs", "php", "rb", "rs"], 0.7, "OS command injection via shell=True/Runtime.exec"),
            "SEC-08": ("_check_unsafe_deserialization", ["py", "java", "php", "rb", "cs", "js", "ts", "go"], 0.8, "Unsafe deserialization via pickle/yaml/ObjectInputStream"),
            "SEC-09": ("_check_xxe", ["py", "java", "js", "ts", "go", "cs", "php", "rb"], 0.65, "XXE via unsafe XML parser"),
            "SEC-14": ("_check_code_injection", ["py", "js", "ts", "java", "php", "rb"], 0.75, "Code injection via eval/exec"),
            "SEC-15": ("_check_xss", ["js", "ts", "jsx", "tsx", "vue", "html", "php", "svelte"], 0.65, "Cross-site scripting via DOM APIs"),
            "SEC-19": ("_check_ssrf", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.6, "SSRF via user-controlled URL"),
            "SEC-23": ("_check_file_inclusion", ["php", "js", "ts", "py", "java", "go"], 0.55, "File inclusion via user input"),

            # ── Web security ──
            "SEC-17": ("_check_csrf", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.6, "CSRF protection missing"),
            "SEC-20": ("_check_open_redirect", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.6, "Open redirect via unvalidated param"),
            "SEC-21": ("_check_file_upload", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.6, "Unrestricted file upload"),
            "SEC-24": ("_check_mass_assignment", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.55, "Mass assignment via req.body"),
            "SEC-25": ("_check_jwt", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.75, "JWT security defects"),
            "SEC-45": ("_check_path_traversal", ["py", "js", "ts", "java", "go", "cs", "php", "rb", "rs"], 0.5, "Path traversal via user input"),
            "SEC-51": ("_check_command_exec", ["py", "js", "ts", "java", "go", "cs", "php", "rb", "rs"], 0.8, "Unsafe direct command execution"),

            # ── Crypto ──
            "SEC-32": ("_check_weak_crypto", ["py", "js", "ts", "java", "go", "cs", "php", "rb", "rs"], 0.75, "Weak cryptographic algorithm"),
            "SEC-33": ("_check_insecure_random", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.7, "Insecure randomness in security context"),
            "SEC-34": ("_check_tls_disabled", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.8, "TLS/SSL validation disabled"),

            # ── Design flaws ──
            "SEC-48": ("_check_zip_slip", ["py", "java", "go", "cs", "php", "rb"], 0.7, "Zip Slip path traversal"),
            "SEC-49": ("_check_memory_safety", ["c", "cpp", "cxx", "rs"], 0.75, "Memory safety violation"),
            "SEC-50": ("_check_error_leak", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.65, "Error handling information leak"),
            "SEC-46": ("_check_race_condition", ["py", "js", "ts", "java", "go", "cs", "rb"], 0.5, "Race condition / TOCTOU"),
            "SEC-47": ("_check_resource_exhaustion", ["py", "js", "ts", "java", "go", "cs"], 0.5, "Resource exhaustion / DoS"),

            # ── Auth / access control ──
            "SEC-18": ("_check_auth_missing", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.35, "Authentication missing on API route"),
            "SEC-22": ("_check_idor", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.35, "IDOR via route param to DB query"),
            "SEC-40": ("_check_cve", ["json", "txt", "xml"], 0.5, "Known CVE dependencies"),
            "SEC-39": ("_check_dep_confusion", ["json", "txt"], 0.3, "Dependency confusion risk"),

            # ── Data protection ──
            "SEC-55": ("_check_plaintext_password", ["py", "js", "ts", "java", "go", "cs", "php", "rb", "sql"], 0.45, "Password stored without hashing"),
            "SEC-56": ("_check_weak_password_policy", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.5, "Weak password policy"),
            "SEC-57": ("_check_audit_log_missing", ["py", "js", "ts", "java", "go", "cs", "php", "rb", "sql"], 0.45, "Sensitive operation without audit log"),

            # ── Design flaws ──
            "SEC-52": ("_check_log_injection", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.5, "Log injection via unsanitized input"),
            "SEC-53": ("_check_integer_overflow", ["py", "js", "ts", "java", "go", "cs", "rb", "c", "cpp"], 0.4, "Integer overflow in arithmetic"),
            "SEC-54": ("_check_null_deref", ["java", "go", "cs", "kt", "swift"], 0.35, "Possible null pointer dereference"),
            "SEC-58": ("_check_brute_force", ["py", "js", "ts", "java", "go", "cs", "php", "rb"], 0.4, "Brute force protection missing"),
            "SEC-59": ("_check_insecure_deletion", ["py", "js", "ts", "java", "go", "cs", "php", "rb", "sql"], 0.45, "Incomplete data deletion"),
        }
        cls._CODE_CHECKS = checks

    @staticmethod
    def _apply_rule(rule: dict[str, Any],
                    content: str,
                    rel_path: str,
                    result: CodeReviewResult) -> None:
        """Apply a single rule's detection patterns against file content.

        Dispatches to the appropriate checker based on rule ID:
        - ``config_*`` pattern types → config file parsers
        - ``regex`` pattern types → pattern matching
        - Code-check rules (by rule_id) → dedicated Python methods
        """
        rule_id = rule.get("id", "UNKNOWN")
        rule_name = rule.get("name", rule_id)
        severity = rule.get("severity", "P2")
        detection = rule.get("detection", {})
        mode = detection.get("mode", "any")
        patterns = detection.get("patterns", [])

        matches: list[dict[str, Any]] = []

        # ── Phase 0: Semgrep AST-level matching ──
        _try_semgrep(content, rel_path, rule_id, matches)

        # ── Phase 1: Python checker from checkers.py ──
        init_checkers()
        checker_matches = run_checker(rule_id, content, rel_path)
        matches.extend(checker_matches)

        # ── Phase 2: run JSON patterns (regex + config engines) ──
        for pat in patterns:
            pat_type = pat.get("type", "regex")
            pat_value = pat.get("value", "")
            confidence = pat.get("confidence", 0.7)

            if pat_type == "regex":
                try:
                    regex = re.compile(pat_value, re.MULTILINE)
                    for m in regex.finditer(content):
                        matches.append({
                            "start": m.start(),
                            "end": m.end(),
                            "matched": m.group()[:200],
                            "confidence": confidence,
                            "pattern": pat_value[:80],
                        })
                except re.error:
                    continue

            elif pat_type == "config_dockerfile":
                matches.extend(
                    match_dockerfile(content, pat_value, confidence)
                )

            elif pat_type == "config_yaml":
                matches.extend(
                    match_yaml_path(content, pat_value, confidence)
                )

            elif pat_type == "config_keyvalue":
                matches.extend(
                    match_keyvalue(content, pat_value, confidence)
                )

        if mode == "all" and len(matches) < len(patterns):
            return
        if mode == "any" and not matches:
            # If no JSON patterns at all but code check found something, still report
            if not patterns and not matches:
                return

        # Deduplicate by position
        seen_positions: set[tuple[int, int]] = set()
        for m in matches:
            pos = (m["start"], m["end"])
            if pos in seen_positions:
                continue
            seen_positions.add(pos)

            line_number = content[:m["start"]].count("\n") + 1
            column = m["start"] - content.rfind("\n", 0, m["start"])

            finding = CodeReviewFinding(
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                file_path=rel_path,
                line_number=line_number,
                column=column,
                matched_text=m["matched"],
                confidence=m["confidence"],
                message=f"[{rule_id}] {rule_name}: {m['matched'][:80]}",
            )
            result.findings.append(finding)

    # ------------------------------------------------------------------
    # Python code checkers — real detection logic, not just regex
    # ------------------------------------------------------------------

    # ── Injection checkers ──

    @staticmethod
    def _check_sql_injection(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for SQL injection via string concatenation in SQL queries."""
        matches: list[dict[str, Any]] = []

        # Only match actual concatenation patterns—parameterized queries (%s, %d, ?) are safe.
        patterns = [
            r"(?:cursor|execute|query|exec)\s*\(\s*(?:f['\"]|['\"][^'\"]*\+|\+ [^'\"]*['\"])",
            # SQL keyword + concatenation: SELECT ... + var
            r"(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;]*\+\s*\w+",
            # Template strings in JS: `SELECT...${var}`
            r"(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\${\w+}",
            # fmt.Sprintf in Go
            r"fmt\.Sprintf\s*\(\s*['\"](?:SELECT|INSERT|UPDATE|DELETE)",
            # ORM raw with variable
            r"\.raw\s*\(\s*(?:f['\"]|['\"][^'\"]*\+|['\"][^'\"]*\w+\s*)",
            # PHP: $sql .= $_GET or $sql = "..." . $input
            r"\$sql\s*[.=].*\$_(?:GET|POST|REQUEST)",
            # Java: Statement + concat
            r"(?:createStatement|prepareStatement)\s*\([^)]*\+",
            # C#: SqlCommand + concat
            r"SqlCommand\s*\(\s*['\"][^'\"]*\+",
            # Go: db.Query with + or Sprintf
            r"db\.(?:Exec|Query|QueryRow)\s*\([^)]*\+",
        ]
        for pat in patterns:
            try:
                for m in re.finditer(pat, content, re.IGNORECASE | re.MULTILINE):
                    # Exclude parameterized: %s, %d, ? parameters are safe
                    text = m.group()
                    if text.endswith("?") or text.endswith("%s") or text.endswith("%d"):
                        continue
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": 0.7,
                        "pattern": "sql_injection_concat",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_os_command_injection(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for OS command injection patterns."""
        matches: list[dict[str, Any]] = []
        patterns = [
            # Python subprocess with shell=True + variable
            (r"subprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True", 0.7),
            # Java Runtime.exec with concat
            (r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+", 0.75),
            # Go exec.Command("sh", "-c", ...)
            (r"exec\.Command\s*\(\s*['\"]sh['\"]\s*,\s*['\"]-c['\"]", 0.8),
            # PHP shell_exec/system/exec
            (r"(?:shell_exec|exec)\s*\(\s*\$", 0.7),
            (r"system\s*\(\s*['\"][^'\"]*\$", 0.65),
            # Backtick with interpolation
            (r"`[^`]*\#\{?\w+[^`]*`", 0.65),
            # Ruby: exec/system/` with variable
            (r"(?:exec|system)\s*\(\s*(?:f['\"]|['\"][^'\"]*\+)", 0.65),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "os_command_injection",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_unsafe_deserialization(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for unsafe deserialization patterns."""
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"(?:pickle\.(?:loads|load)|shelve\.open)\s*\(", 0.85, "unsafe pickle"),
            (r"yaml\.(?:load|load_all)\s*\([^)]*(?:(?!SafeLoader|CSafeLoader).)", 0.8, "unsafe yaml.load"),
            (r"ObjectInputStream\.(?:readObject|readUnshared)\s*\(", 0.9, "Java deserialize"),
            (r"\bunserialize\s*\(\s*\$", 0.85, "PHP unserialize"),
            (r"Marshal\.(?:load|restore)\s*\(", 0.85, "Ruby marshal"),
            (r"new\s+BinaryFormatter\s*\([^)]*\).*\.Deserialize\s*\(", 0.85, ".NET BinaryFormatter"),
            (r"XMLDecoder\s*\(", 0.85, "Java XMLDecoder"),
            (r"node-serialize|node_serialize", 0.7, "Node.js serialize"),
        ]
        for pat, conf, _ in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "unsafe_deserialization",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_xxe(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for XXE via unsafe XML parser config."""
        matches: list[dict[str, Any]] = []
        patterns = [
            # Java DocumentBuilderFactory without DTD disable
            (r"DocumentBuilderFactory\.newInstance\(\)(?![\s\S]*?setFeature.*disallow-doctype-dec)", 0.65, "Java XXE"),
            # C# XmlDocument with XmlResolver set
            (r"new\s+XmlDocument\s*\([^)]*\)\s*\{[^}]*\bXmlResolver\s*=", 0.7, ".NET XXE"),
            # PHP simplexml without entity disable
            (r"simplexml_load_string\s*\(", 0.6, "PHP simplexml"),
            # Go xml.Decoder without Strict
            (r"xml\.Decoder\s*\{[^}]*\bStrict\s*=\s*false", 0.7, "Go XXE"),
            # lxml without resolve_entities
            (r"lxml\.(?:fromstring|parse|XML)\s*\([^)]*\bresolve_entities\s*(?!=\s*False)", 0.65, "Python lxml XXE"),
        ]
        for pat, conf, _ in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "xxe",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_code_injection(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for code injection via eval/exec/Function with untrusted input."""
        matches: list[dict[str, Any]] = []
        patterns = [
            # eval/exec with user input variable names
            (r"\b(?:eval|exec)\s*\(\s*(?:req|request|input|user|data|body|query|params)\b", 0.85, "eval/exec user input"),
            # JS Function() with untrusted input
            (r"\bFunction\s*\(\s*(?:req|request|input|user|data)\b", 0.8, "Function() user input"),
            # Java ScriptEngine
            (r"ScriptEngine\.eval\s*\(\s*(?:req|request|input|user)\b", 0.85, "ScriptEngine.eval"),
            # PHP create_function
            (r"create_function\s*\(\s*\$", 0.75, "PHP create_function"),
            # PHP assert with variable
            (r"\bassert\s*\(\s*\$_(?:GET|POST|REQUEST)", 0.85, "PHP assert injection"),
            # Ruby eval/instance_eval with variable
            (r"(?:eval|instance_eval)\s*\(\s*(?:params|input|user|data)", 0.75, "Ruby eval"),
            # Python eval(__import__ pattern)
            (r"eval\s*\(\s*__import__\s*\(", 0.85, "Python eval + import"),
        ]
        for pat, conf, _ in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "code_injection",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_xss(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for XSS via dangerous DOM APIs with untrusted data."""
        matches: list[dict[str, Any]] = []
        patterns = [
            # innerHTML with variable
            (r"innerHTML\s*=\s*(?!['\"])\w+", 0.65, "innerHTML assignment"),
            # React dangerouslySetInnerHTML
            (r"dangerouslySetInnerHTML\s*=\s*\{*\s*__html", 0.75, "React dangerouslySetInnerHTML"),
            # Vue v-html
            (r"v-html\s*=\s*['\"]?\s*\w+", 0.65, "Vue v-html"),
            # document.write with variable
            (r"document\.write\s*\(\s*\w+", 0.65, "document.write"),
            # jQuery .html() with variable
            (r"\.html\(\s*(?!['\"])\w+", 0.6, "jQuery .html()"),
            # Svelte {@html}
            (r"\{@html\s+\w+", 0.65, "Svelte @html"),
            # Template safe filter
            (r"\|\s*safe\s*\}", 0.5, "safe filter"),
            # Angular innerHtml binding
            r"\[innerHtml\]\s*=\s*\w+",
        ]
        for pat in patterns:
            try:
                if isinstance(pat, tuple):
                    pat, conf, _ = pat
                else:
                    conf = 0.6
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "xss",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_ssrf(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for SSRF: user-controlled URL passed to HTTP client."""
        matches: list[dict[str, Any]] = []
        patterns = [
            # Python requests.get(var) where var is user-like
            (r"requests\.(?:get|post|put|delete|patch|request)\s*\(\s*\w+(?:url|input|user|param|query|body|data|host|endpoint)?\b", 0.6),
            # JS axios.get(var)
            (r"axios\.(?:get|post|put|delete|patch|request)\s*\(\s*\w+(?:url|input|user|param|query|body|data)?\b", 0.6),
            # JS fetch(var)
            (r"fetch\s*\(\s*\w+(?:url|input|user|param|query|body|data)?\b", 0.55),
            # Java HttpClient.execute
            (r"HttpClient\.(?:execute|SendAsync)\s*\(\s*\w+", 0.6),
            # Go http.Get(var) / http.Post(var)
            (r"http\.(?:Get|Post|NewRequest)\s*\(\s*\w+", 0.55),
            # Ruby open-uri
            (r"open-uri\s*\(\s*\w+", 0.55),
            # PHP curl_exec with variable
            (r"curl_exec\s*\(\s*\$", 0.6),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "ssrf",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_file_inclusion(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for LFI/RFI via user-controlled file paths."""
        matches: list[dict[str, Any]] = []
        patterns = [
            # PHP include/require with user input
            (r"(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", 0.85),
            # PHP include with variable in path
            (r"(?:include|require)\s*\(\s*['\"][^'\"]*\$\{?\w+", 0.7),
            # JS fs.readFile with variable
            (r"fs\.readFile\s*\(\s*\w+(?:input|user|param|query|path|file)?\b", 0.6),
            # Python open with user variable
            (r"\bopen\s*\(\s*\w+(?:input|user|filename|filepath|path)\b\s*[),]", 0.55),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "file_inclusion",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_csrf(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for CSRF protection bypasses."""
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"(?i)@csrf\.exempt\b", 0.85, "CSRF exempt"),
            (r"(?i)\bcsrf_exempt\b", 0.85, "CSRF exempt"),
            (r"(?i)protect_from_forgery\s+(?:except|skip)", 0.7, "Forgery protection bypass"),
            (r"(?i)@CrossOrigin\([^)]*allowCredentials", 0.6, "CORS + CSRF risk"),
        ]
        for pat, conf, _ in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "csrf",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_open_redirect(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for open redirect via unvalidated parameters."""
        matches: list[dict[str, Any]] = []
        patterns = [
            # Django redirect(request.GET.get('next'))
            (r"redirect\s*\(\s*(?:request|req)\.(?:GET|args|query|params)\.get\s*\(\s*['\"](?:next|url|redirect|return)['\"]", 0.7),
            # Flask redirect(request.args.get(...))
            (r"redirect\s*\(\s*(?:request|req)\.(?:args|values)\s*\[?\s*['\"](?:next|url|redirect)['\"]", 0.65),
            # Express res.redirect(req.query.x)
            (r"res\.redirect\s*\(\s*(?:req|request)\.", 0.6),
            # Rails redirect_to params
            (r"redirect_to\s+(?:params|req|request)", 0.6),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "open_redirect",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_file_upload(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for unrestricted file upload."""
        matches: list[dict[str, Any]] = []
        patterns = [
            # Flask/Django file.save()
            (r"(?:request\.files|request\.FILES|request->file|req\.file|upload|form\.file)\s*\(?[^)]*\)?\.\s*(?:save|store|put|write)", 0.65),
            # Express multer with no validation
            (r"multer\s*\(\s*\{[^}]*\bdest\b[^}]*\}\s*\)", 0.6),
            # Spring MultipartFile.transferTo
            (r"MultipartFile\.transferTo\s*\(", 0.65),
            # Laravel store
            (r"->store\s*\(\s*\$request", 0.65),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "file_upload",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_mass_assignment(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for mass assignment via req.body → model."""
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"(?:User|Model|Entity)\.(?:create|update|save)\s*\(\s*(?:req|request)\.(?:body|params|data|json)", 0.65),
            (r"(?:create|build|assign_attributes)\s*\(\s*(?:params|request_params)\b", 0.6),
            (r"TryUpdateModel\s*\([^)]*\b(?:Request|Input)\b", 0.6),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "mass_assignment",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_jwt(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for JWT security defects."""
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"['\"]alg['\"]\s*:\s*['\"]none['\"]", 0.9, "alg none"),
            (r"(?i)jwt\.(?:sign|encode)\s*\([^)]*['\"](?:secret|jwt_secret|my_secret)['\"]", 0.75, "weak JWT secret"),
            (r"(?i)\bJWT_SECRET\s*[:=]\s*['\"](?:secret|changeme|password)['\"]", 0.8, "hardcoded JWT secret"),
            (r"(?i)\balgorithm\s*=\s*['\"]none['\"]", 0.9, "alg none kwarg"),
        ]
        for pat, conf, _ in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "jwt_defect",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_path_traversal(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for path traversal via user-controlled file paths."""
        matches: list[dict[str, Any]] = []
        patterns = [
            # os.path.join with user variable
            (r"os\.path\.join\s*\([^)]*\w+(?:input|user|file|name|path|filename)?\b\s*,", 0.55),
            # Path.Combine with variable
            (r"Path\.Combine\s*\([^)]*\w+(?:input|user|file|name|path|fileName|filename)?\b", 0.6),
            # PHP file functions with $_GET/$_POST
            (r"(?:file_get_contents|unlink|file_put_contents|fopen)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", 0.8),
            # new File with variable
            (r"new\s+File\s*\(\s*\w+(?:input|user|file|name|path|fileName)?\b", 0.5),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "path_traversal",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_command_exec(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for unsafe direct command execution."""
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"os\.system\s*\(", 0.85),
            (r"subprocess\.(?:call|Popen|run)\s*\(", 0.75),
            (r"Runtime\.getRuntime\(\)\.exec\s*\(", 0.85),
            (r"exec\.Command\s*\(", 0.8),
            (r"child_process\.(?:exec|execSync|execFile|spawn)\s*\(", 0.8),
            (r"Process\.Start\s*\([^)]*['\"](?:cmd|bash|sh|powershell)", 0.8),
            (r"ProcessBuilder\s*\(", 0.75),
            (r"std::process::Command\s*::\s*new", 0.8),
            (r"ShellExecute\s*\(", 0.75),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "direct_command_exec",
                    })
            except re.error:
                continue
        return matches

    # ── Crypto checkers ──

    @staticmethod
    def _check_weak_crypto(content: str, rel_path: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"(?i)\bhashlib\.md5\b|\bMessageDigest\.getInstance\s*\(\s*['\"]MD5", 0.85),
            (r"(?i)\bhashlib\.sha1\b|\bMessageDigest\.getInstance\s*\(\s*['\"]SHA-?1", 0.85),
            (r"(?i)AES/ECB/", 0.85),
            (r"(?i)DES(?:CryptoServiceProvider|\.new)\b", 0.8),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "weak_crypto",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_insecure_random(content: str, rel_path: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"^import random$|^from random import", 0.75),
            (r"Math\.random\s*\(\s*\)", 0.7),
            (r"java\.util\.Random\b", 0.8),
            (r"new\s+Random\s*\(\s*\)", 0.65),
            (r"\brand\s*\(\s*\)|\bmt_rand\s*\(\s*\)", 0.7),
            (r"math/rand\"", 0.7),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "insecure_random",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_tls_disabled(content: str, rel_path: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"verify\s*=\s*(?:False|false|0)", 0.8),
            (r"rejectUnauthorized\s*[:=]\s*(?:false|0)", 0.85),
            (r"InsecureSkipVerify\s*[:=]\s*(?:true|True)", 0.85),
            (r"ServerCertificateValidationCallback\s*[:=]\s*\{[^}]*true\s*\}", 0.85),
            (r"(?i)VERIFY_NONE", 0.85),
            (r"(?i)CURLOPT_SSL_VERIFYPEER\s*[:=]\s*0", 0.8),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "tls_disabled",
                    })
            except re.error:
                continue
        return matches

    # ── Design flaw checkers ──

    @staticmethod
    def _check_zip_slip(content: str, rel_path: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"(?:zipfile|tarfile)\.(?:extractall|extract)\s*\(", 0.7),
            (r"ZipInputStream\.getNextEntry", 0.65),
            (r"extractall\s*\([^)]*", 0.6),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "zip_slip",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_memory_safety(content: str, rel_path: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"\bgets\s*\(", 0.85),
            (r"\bstrcpy\s*\(", 0.75),
            (r"\bsprintf\s*\(", 0.6),
            (r"\bscanf\s*\(", 0.55),
            (r"\bstrcat\s*\(", 0.7),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "memory_safety",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_error_leak(content: str, rel_path: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"traceback\.format_exc\s*\(", 0.75),
            (r"err\.stack", 0.65),
            (r"e\.ToString\(\)", 0.65),
            (r"print_exc\s*\(", 0.7),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "error_leak",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_race_condition(content: str, rel_path: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"(?i)if\s+os\.path\.exists\b", 0.4),
            (r"if\s+not\s+os\.path\.exists.*[\\\n].*\b(?:open|remove|rename)\b", 0.5),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "race_condition",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_resource_exhaustion(content: str, rel_path: str) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        patterns = [
            (r"while\s+True\s*:", 0.5),
            (r"(?i)requests\.get\s*\([^)]*\)\s*(?:(?!timeout).)*$", 0.4),
        ]
        for pat, conf in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": conf,
                        "pattern": "resource_exhaustion",
                    })
            except re.error:
                continue
        return matches

    # ── Auth / access control checkers ──

    @staticmethod
    def _check_auth_missing(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for API routes missing authentication middleware/decorators."""
        matches: list[dict[str, Any]] = []

        # Django: @app.route / @csrf_exempt without @login_required nearby
        for m in re.finditer(r"@(?:app\.(?:route|get|post|put|delete|patch)|csrf_exempt)\s*\(", content):
            chunk = content[m.end():m.end() + 500]
            has_login = bool(re.search(r"@(?:login_required|jwt_required|permission_required|user_passes_test)", chunk))
            has_before = bool(re.search(r"@app\.before_request", content))
            if not has_login and not has_before:
                matches.append({
                    "start": m.start(), "end": m.end() + 30,
                    "matched": m.group()[:200], "confidence": 0.45,
                    "pattern": "django_route_no_auth",
                })

        # Flask: route without @login_required
        for m in re.finditer(r"@app\.(?:route|get|post|put|delete)\(", content):
            chunk = content[m.end():m.end() + 500]
            if not re.search(r"@login_required", chunk) and "@app.before_request" not in content:
                matches.append({
                    "start": m.start(), "end": m.end() + 30,
                    "matched": m.group()[:200], "confidence": 0.4,
                    "pattern": "flask_route_no_auth",
                })

        # Express: route without auth middleware
        for m in re.finditer(r"router\.(?:get|post|put|delete|patch)\s*\(\s*['\"][^'\"]*['\"]\s*,", content):
            chunk = content[m.end():m.end() + 300]
            if not re.search(r"(?:verifyToken|isAuthenticated|authenticate|authMiddleware|requireAuth)", chunk):
                matches.append({
                    "start": m.start(), "end": m.end() + 30,
                    "matched": m.group()[:200], "confidence": 0.35,
                    "pattern": "express_route_no_auth",
                })

        return matches

    @staticmethod
    def _check_idor(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for IDOR: user input param passed to query without ownership check."""
        matches: list[dict[str, Any]] = []

        # Route param used directly in database query (Express: :param, Flask: <param>)
        for m in re.finditer(r"(?:router|app)\.(?:get|post|put|delete|patch)\s*\(\s*['\"][^'\"]*[:<](\w+)[>'\"]", content):
            param = m.group(1)
            # Check if the same param appears in a DB query in the function
            chunk = content[m.end():m.end() + 500]
            if re.search(rf"(?:find|findById|query|get|where|filter)\s*\([^)]*{param}", chunk, re.IGNORECASE):
                # Check for ownership/authorization check
                if not re.search(r"(?:owner|user_id|current_user|req\.user|userId|authorize|check|can_|permission)", chunk, re.IGNORECASE):
                    matches.append({
                        "start": m.start(), "end": m.end() + 30,
                        "matched": m.group()[:200], "confidence": 0.4,
                        "pattern": "idor_route_param_to_query",
                    })

        return matches

    @staticmethod
    def _check_dep_confusion(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for dependency confusion in lockfile/manifest."""
        matches: list[dict[str, Any]] = []
        basename = PurePosixPath(rel_path).name

        # Check package.json for suspicious entries
        if basename in ("package.json", "package-lock.json"):
            try:
                data = json.loads(content)
                deps = {**(data.get("dependencies", {}) or {}), **(data.get("devDependencies", {}) or {})}
                for pkg_name, version in deps.items():
                    if not isinstance(version, str):
                        continue
                    suspicious = (
                        version in ("*", "") or
                        version.startswith("file:") or
                        version.startswith("http:")
                    )
                    if suspicious:
                        matches.append({
                            "start": content.find(f'"{pkg_name}"') if f'"{pkg_name}"' in content else 0,
                            "end": 0,
                            "matched": f"{pkg_name}@{version}",
                            "confidence": 0.5,
                            "pattern": "dep_confusion_check",
                        })
            except (json.JSONDecodeError, AttributeError):
                pass

        # Check requirements.txt for potentially confusing packages
        if basename in ("requirements.txt", "Pipfile"):
            common = {"django","flask","requests","numpy","pandas","pytest","fastapi","sqlalchemy",
                      "celery","redis","psycopg2","boto3","scipy","scikit-learn","pillow","lxml","click"}
            for m in re.finditer(r"^([a-zA-Z_][a-zA-Z0-9_.-]*)[=~<>!]", content, re.MULTILINE):
                pkg = m.group(1).lower()
                if pkg not in common and not pkg.startswith("_"):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": pkg,
                        "confidence": 0.35,
                        "pattern": "dep_confusion_check",
                    })

        return matches

    @staticmethod
    def _check_cve(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check dependencies against known CVE database."""
        from kasra.scanner.checkers import check_cve
        return check_cve(content, rel_path)

    @staticmethod
    def _check_integer_overflow(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for potential integer overflow."""
        matches: list[dict[str, Any]] = []

        # balance/amount -= value without >= guard
        for m in re.finditer(r"(?:balance|amount|total|count|quantity|credits?)\s*-=\s*\w+", content):
            pre_lines = content[max(0, content.rfind("\n", 0, m.start()) - 300):m.start()]
            if not re.search(r"(?:>=|>=|if\s+\w+\s*[><])\s*\w+(?:balance|amount|total|credits)", pre_lines):
                matches.append({
                    "start": m.start(), "end": m.end(),
                    "matched": m.group()[:200], "confidence": 0.45,
                    "pattern": "balance_sub_no_guard",
                })

        # user input * multiplier pattern
        for m in re.finditer(r"(?:user_input|userInput|input|req|body)\b[^;]*[*]\s*(?:price|amount|count|rate|qty)", content, re.IGNORECASE):
            matches.append({
                "start": m.start(), "end": m.end(),
                "matched": m.group()[:200], "confidence": 0.5,
                "pattern": "user_input_mul",
            })

        return matches

    @staticmethod
    def _check_null_deref(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for possible null pointer dereference."""
        matches: list[dict[str, Any]] = []
        lines = content.split("\n")
        for i, line in enumerate(lines):
            # Pattern: a nullable return + next line uses it without check
            for m in re.finditer(r"(?:\.find(?:ById|One|First)?|\.getOrNull|Optional\.ofNullable|FirstOrDefault|getFirst)\s*\([^)]*\)", line):
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    if re.search(r"\.\s*\w+\s*\(", next_line):
                        ctx = line + "\n" + next_line
                        if not re.search(r"\bisPresent\b|\bifNull\b|orElse\b|orElseThrow\b|!= null|!= nil|!= None|\bisNotNull\b", ctx):
                            matches.append({
                                "start": sum(len(l) + 1 for l in lines[:i]),
                                "end": sum(len(l) + 1 for l in lines[:i]),
                                "matched": line.strip()[:200],
                                "confidence": 0.4,
                                "pattern": "possible_null_deref",
                            })
        return matches

    # ── Data protection checkers ──

    @staticmethod
    def _check_plaintext_password(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for passwords stored without hashing."""
        matches: list[dict[str, Any]] = []

        # INSERT INTO ... password ... without hash function
        for m in re.finditer(r"(?i)(?:INSERT\s+INTO\s+\w+\s*\([^)]*password[^)]*\))", content):
            after = content[m.end():m.end() + 200]
            if not re.search(r"(?i)(?:bcrypt|argon2|scrypt|hash(?!\s*map)|pbkdf2|sha)", after):
                matches.append({
                    "start": m.start(), "end": m.end(),
                    "matched": m.group()[:200], "confidence": 0.55,
                    "pattern": "password_insert_no_hash",
                })

        # password = "plaintext" without hash nearby
        for m in re.finditer(r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{3,}['\"]", content):
            ctx = content[max(0, m.start() - 300):m.end() + 100]
            if not re.search(r"(?:bcrypt|argon2|scrypt|hash|pbkdf2|make_password)", ctx):
                matches.append({
                    "start": m.start(), "end": m.end(),
                    "matched": m.group()[:200], "confidence": 0.5,
                    "pattern": "password_assignment_plain",
                })

        return matches

    @staticmethod
    def _check_weak_password_policy(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for weak password policies."""
        matches: list[dict[str, Any]] = []

        for m in re.finditer(r"(?i)(?:min[_\.]?(?:length|len|size)|minLength)\s*[:=<>!]+\s*([456])\b", content):
            matches.append({
                "start": m.start(), "end": m.end(),
                "matched": m.group()[:200], "confidence": 0.65,
                "pattern": "min_length_too_short",
            })

        for m in re.finditer(r"(?i)(?:len|length)\s*\(\s*(?:password|passwd|pwd)\s*\)\s*[<]\s*([6789])", content):
            matches.append({
                "start": m.start(), "end": m.end(),
                "matched": m.group()[:200], "confidence": 0.6,
                "pattern": "password_length_too_small",
            })

        return matches

    @staticmethod
    def _check_audit_log_missing(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for sensitive operations without audit log entries."""
        matches: list[dict[str, Any]] = []

        # DELETE/UPDATE sensitive tables without audit log
        for m in re.finditer(r"(?i)(?:DELETE|UPDATE)\s+(?:FROM\s+)?(?:users?|accounts?|transactions?|employees?)\s+WHERE", content):
            after = content[m.end():m.end() + 300]
            if not re.search(r"(?i)(?:audit|log|record|insert.*log|create.*audit)", after):
                matches.append({
                    "start": m.start(), "end": m.end(),
                    "matched": m.group()[:200], "confidence": 0.5,
                    "pattern": "sensitive_op_no_audit",
                })

        # Grant/revoke without audit
        for m in re.finditer(r"(?i)(?:GRANT|REVOKE)\s+.*\s+(?:TO|FROM)\s+\w+", content):
            after = content[m.end():m.end() + 300]
            if not re.search(r"(?i)(?:audit|log)", after):
                matches.append({
                    "start": m.start(), "end": m.end(),
                    "matched": m.group()[:200], "confidence": 0.55,
                    "pattern": "permission_change_no_audit",
                })

        return matches

    # ── Design flaw checkers ──

    @staticmethod
    def _check_log_injection(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for unsanitized user input in log statements."""
        matches: list[dict[str, Any]] = []
        patterns = [
            r"logging\.(?:info|debug|error|warning)\s*\(\s*(?:f['\"]|['\"][^'\"]*\+\s*\w+|['\"][^'\"]*\{[^}]+\})",
            r"log\.(?:info|debug|error|warn)\s*\(\s*(?:f['\"]|['\"][^'\"]*\+\s*\w+)",
            r"logger\.(?:info|debug|error|warn)\s*\(\s*(?:f['\"]|['\"][^'\"]*\+\s*\w+)",
            r"print\s*\(\s*['\"][^'\"]*\+\s*\w+(?:input|user|param|data|body|req)",
        ]
        for pat in patterns:
            try:
                for m in re.finditer(pat, content, re.MULTILINE):
                    matches.append({
                        "start": m.start(), "end": m.end(),
                        "matched": m.group()[:200], "confidence": 0.55,
                        "pattern": "log_injection",
                    })
            except re.error:
                continue
        return matches

    @staticmethod
    def _check_brute_force(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for login endpoints without rate limiting."""
        matches: list[dict[str, Any]] = []

        for m in re.finditer(r"(?i)(?:def\s+login|def\s+signin|function\s+login)\s*\(", content):
            after = content[m.end():m.end() + 500]
            if not re.search(r"(?i)(?:rate.?limit|throttle|lockout|fail.?count|max.?attempt|captcha)", after):
                matches.append({
                    "start": m.start(), "end": m.end(),
                    "matched": m.group()[:200], "confidence": 0.45,
                    "pattern": "login_no_rate_limit",
                })

        return matches

    @staticmethod
    def _check_insecure_deletion(content: str, rel_path: str) -> list[dict[str, Any]]:
        """Check for incomplete data deletion."""
        matches: list[dict[str, Any]] = []

        for m in re.finditer(r"(?i)(?:is_deleted\s*=\s*True|deleted_at\s*=|deleted_flag\s*=\s*1)", content):
            ctx = content[max(0, m.start() - 200):m.end() + 300]
            if not re.search(r"(?i)(?:cleanup|purge|vacuum|physical.?delete|hard.?delete|archive)", ctx):
                matches.append({
                    "start": m.start(), "end": m.end(),
                    "matched": m.group()[:200], "confidence": 0.5,
                    "pattern": "soft_delete_no_cleanup",
                })

        return matches

    # ------------------------------------------------------------------
    # Config-parsing engines
    # ------------------------------------------------------------------

    @staticmethod
    def _match_dockerfile(content: str,
                          pattern: str,
                          confidence: float) -> list[dict[str, Any]]:
        """Match Dockerfile instructions structurally.

        Pattern format: ``INSTRUCTION:value_regex``
        Example: ``FROM:\\s*\\S+:\\s*latest`` matches ``FROM python:latest``
        """
        results: list[dict[str, Any]] = []
        if ":" not in pattern:
            return results

        instr, value_re = pattern.split(":", 1)
        instr = instr.strip().upper()

        # Parse Dockerfile instructions line by line
        lines = content.split("\n")
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Check if line starts with the instruction
            if not stripped.upper().startswith(instr):
                continue
            target = stripped[len(instr):].strip()
            try:
                if re.search(value_re, target, re.IGNORECASE):
                    # Calculate absolute position in content
                    pos = sum(len(l) + 1 for l in lines[:i])
                    results.append({
                        "start": pos,
                        "end": pos + len(line),
                        "matched": line.strip()[:200],
                        "confidence": confidence,
                        "pattern": pattern,
                    })
            except re.error:
                continue
        return results

    @staticmethod
    def _match_yaml_path(content: str,
                         pattern: str,
                         confidence: float) -> list[dict[str, Any]]:
        """Match YAML key paths with value regex.

        Pattern format: ``key.path:value_regex``
        Example: ``spec.containers.securityContext.privileged:true``
        """
        results: list[dict[str, Any]] = []
        if ":" not in pattern:
            return results

        path_str, value_re = pattern.split(":", 1)
        keys = [k.strip() for k in path_str.split(".")]

        lines = content.split("\n")
        current_path: list[str] = []
        indent_stack: list[int] = []

        for i, line in enumerate(lines):
            if not line.strip() or line.strip().startswith("#") or line.strip().startswith("---"):
                if line.strip() and not line.strip().startswith("#"):
                    continue
                continue

            stripped = line.rstrip()
            indent = len(line) - len(line.lstrip())
            key_part = stripped.lstrip()

            if ":" in key_part:
                key = key_part.split(":", 1)[0].strip()
                value = key_part.split(":", 1)[1].strip().strip('"').strip("'") if ":" in key_part else ""

                # Pop stack to correct level
                while indent_stack and indent <= indent_stack[-1]:
                    indent_stack.pop()
                    if current_path:
                        current_path.pop()
                    if indent_stack and indent <= indent_stack[-1]:
                        if current_path:
                            current_path.pop()

                indent_stack.append(indent)
                current_path.append(key)

                # Check if current path matches
                if current_path == keys:
                    try:
                        if re.search(value_re, value, re.IGNORECASE):
                            pos = sum(len(l) + 1 for l in lines[:i])
                            results.append({
                                "start": pos,
                                "end": pos + len(line),
                                "matched": line.strip()[:200],
                                "confidence": confidence,
                                "pattern": pattern,
                            })
                    except re.error:
                        continue

        return results

    @staticmethod
    def _match_keyvalue(content: str,
                        pattern: str,
                        confidence: float) -> list[dict[str, Any]]:
        """Match key=value pairs in config files (.env, .properties).

        Pattern format: ``KEY:value_regex``
        Example: ``SECRET_KEY:changeme``
        """
        results: list[dict[str, Any]] = []
        if ":" not in pattern:
            return results

        key_name, value_re = pattern.split(":", 1)

        for line in content.split("\n"):
            stripped = line.strip()
            # Skip comments and empty lines
            if not stripped or stripped.startswith("#") or stripped.startswith(";"):
                continue
            if "=" not in stripped and ":" not in stripped:
                continue

            sep = "=" if "=" in stripped else ":"
            k, v = stripped.split(sep, 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")

            if k.upper() == key_name.upper():
                try:
                    if re.search(value_re, v, re.IGNORECASE):
                        pos = content.find(line)
                        results.append({
                            "start": max(0, pos),
                            "end": pos + len(line),
                            "matched": line.strip()[:200],
                            "confidence": confidence,
                            "pattern": pattern,
                        })
                except re.error:
                    continue
        return results

    # SEC-40 is handled by standard pattern matching from the JSON rule patterns
