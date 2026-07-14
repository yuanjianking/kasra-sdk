"""Code security checkers — pattern matching logic extracted from scanner.py.

Each checker is a module-level function ``(content, rel_path) -> list[dict]``.
"""

from __future__ import annotations

import json
import re
from typing import Any


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_CODE_CHECKS: dict[str, tuple[str, list[str], float, str]] = {}


def init_checkers() -> dict[str, tuple[str, list[str], float, str]]:
    """Populate and return the checker registry. Idempotent."""
    if _CODE_CHECKS:
        return _CODE_CHECKS

    _CODE_CHECKS.update({
        "SEC-05": ("check_sql_injection", ["py","js","ts","java","go","cs","php","rb"], 0.65, "SQL injection"),
        "SEC-06": ("check_nosql", ["py","js","ts","java","go","cs","php","rb"], 0.65, "NoSQL injection"),
        "SEC-07": ("check_os_command_injection", ["py","js","ts","java","go","cs","php","rb","rs"], 0.7, "OS command injection"),
        "SEC-08": ("check_unsafe_deserialization", ["py","java","php","rb","cs","js","ts","go"], 0.8, "Unsafe deserialization"),
        "SEC-09": ("check_xxe", ["py","java","js","ts","go","cs","php","rb"], 0.65, "XXE"),
        "SEC-10": ("check_ldap", ["py","java","cs","php","rb","js","ts"], 0.7, "LDAP injection"),
        "SEC-11": ("check_ssti", ["py","java","js","ts","go","php","rb","cs"], 0.65, "SSTI"),
        "SEC-12": ("check_header_injection", ["py","js","ts","php","rb","java","go"], 0.5, "Header injection"),
        "SEC-13": ("check_proto_pollution", ["js","ts","jsx","tsx"], 0.65, "Prototype pollution"),
        "SEC-14": ("check_code_injection", ["py","js","ts","java","php","rb"], 0.75, "Code injection"),
        "SEC-15": ("check_xss", ["js","ts","jsx","tsx","vue","html","php","svelte"], 0.65, "XSS"),
        "SEC-17": ("check_csrf", ["py","js","ts","java","go","cs","php","rb"], 0.6, "CSRF"),
        "SEC-18": ("check_auth_missing", ["py","js","ts","java","go","cs","php","rb"], 0.35, "Auth missing"),
        "SEC-19": ("check_ssrf", ["py","js","ts","java","go","cs","php","rb"], 0.6, "SSRF"),
        "SEC-20": ("check_open_redirect", ["py","js","ts","java","go","cs","php","rb"], 0.6, "Open redirect"),
        "SEC-21": ("check_file_upload", ["py","js","ts","java","go","cs","php","rb"], 0.6, "File upload"),
        "SEC-22": ("check_idor", ["py","js","ts","java","go","cs","php","rb"], 0.35, "IDOR"),
        "SEC-23": ("check_file_inclusion", ["php","js","ts","py","java","go"], 0.55, "File inclusion"),
        "SEC-24": ("check_mass_assignment", ["py","js","ts","java","go","cs","php","rb"], 0.55, "Mass assignment"),
        "SEC-25": ("check_jwt", ["py","js","ts","java","go","cs","php","rb"], 0.75, "JWT defects"),
        "SEC-27": ("check_session_defects", ["py","js","ts","java","go","cs","php","rb"], 0.55, "Session defects"),
        "SEC-28": ("check_oauth", ["py","js","ts","java","go","cs","php"], 0.5, "OAuth defects"),
        "SEC-29": ("check_websocket", ["py","js","ts","java","go","cs"], 0.6, "WebSocket security"),
        "SEC-30": ("check_grpc", ["go","py","java","js","ts","rs","cs"], 0.65, "gRPC security"),
        "SEC-31": ("check_graphql", ["py","js","ts","java","go","rb"], 0.6, "GraphQL security"),
        "SEC-32": ("check_weak_crypto", ["py","js","ts","java","go","cs","php","rb","rs"], 0.75, "Weak crypto"),
        "SEC-33": ("check_insecure_random", ["py","js","ts","java","go","cs","php","rb"], 0.7, "Insecure random"),
        "SEC-34": ("check_tls_disabled", ["py","js","ts","java","go","cs","php","rb"], 0.8, "TLS disabled"),
        "SEC-35": ("check_insecure_cert", ["py","java","js","ts","go","cs","rb"], 0.6, "Insecure cert"),
        "SEC-39": ("check_dep_confusion", ["json","txt"], 0.3, "Dependency confusion"),
        "SEC-43": ("check_observability_leak", ["py","js","ts","java","go","yaml","yml"], 0.5, "Observability leak"),
        "SEC-45": ("check_path_traversal", ["py","js","ts","java","go","cs","php","rb","rs"], 0.5, "Path traversal"),
        "SEC-46": ("check_race_condition", ["py","js","ts","java","go","cs","rb"], 0.5, "Race condition"),
        "SEC-47": ("check_resource_exhaustion", ["py","js","ts","java","go","cs"], 0.5, "Resource exhaust"),
        "SEC-48": ("check_zip_slip", ["py","java","go","cs","php","rb"], 0.7, "Zip slip"),
        "SEC-49": ("check_memory_safety", ["c","cpp","cxx","rs"], 0.75, "Memory safety"),
        "SEC-50": ("check_error_leak", ["py","js","ts","java","go","cs","php","rb"], 0.65, "Error leak"),
        "SEC-51": ("check_command_exec", ["py","js","ts","java","go","cs","php","rb","rs"], 0.8, "Command exec"),
        "SEC-52": ("check_log_injection", ["py","js","ts","java","go","cs","php","rb"], 0.5, "Log injection"),
        "SEC-53": ("check_integer_overflow", ["py","js","ts","java","go","cs","rb","c","cpp"], 0.4, "Integer overflow"),
        "SEC-54": ("check_null_deref", ["java","go","cs","kt","swift"], 0.35, "Null deref"),
        "SEC-55": ("check_plaintext_password", ["py","js","ts","java","go","cs","php","rb","sql"], 0.45, "Plaintext password"),
        "SEC-56": ("check_weak_password_policy", ["py","js","ts","java","go","cs","php","rb"], 0.5, "Weak password policy"),
        "SEC-57": ("check_audit_log_missing", ["py","js","ts","java","go","cs","php","rb","sql"], 0.45, "Audit log missing"),
        "SEC-58": ("check_brute_force", ["py","js","ts","java","go","cs","php","rb"], 0.4, "Brute force"),
        "SEC-59": ("check_insecure_deletion", ["py","js","ts","java","go","cs","php","rb","sql"], 0.45, "Insecure deletion"),
        "SEC-60": ("check_webview", ["kt","java","swift","dart"], 0.6, "WebView insecure"),
        "SEC-61": ("check_mobile_storage", ["kt","java","swift","dart"], 0.6, "Mobile storage"),
        "SEC-62": ("check_deep_link", ["xml","kt","java","plist","swift"], 0.55, "Deep link"),
        "SEC-64": ("check_cert_pinning", ["kt","java","swift","dart"], 0.5, "Cert pinning"),
        "SEC-66": ("check_clipboard", ["kt","java","swift","dart","js","ts"], 0.55, "Clipboard"),
    })
    return _CODE_CHECKS


CHECKER_FUNCS: dict[str, callable] = {}


def get_checker_func(name: str) -> callable | None:
    """Lazy-import checker function by name."""
    if not CHECKER_FUNCS:
        # Populate on first call
        checkers_mod = __import__("kasra.scanner.checkers", fromlist=["_fake"])
        for attr in dir(checkers_mod):
            if attr.startswith("check_"):
                CHECKER_FUNCS[attr] = getattr(checkers_mod, attr)
    return CHECKER_FUNCS.get(name)


def run_checker(rule_id: str, content: str, rel_path: str) -> list[dict[str, Any]]:
    """Run the checker for *rule_id* against *content*.

    Returns:
        List of match dicts with keys ``start``, ``end``, ``matched``,
        ``confidence``, ``pattern``.
    """
    init_checkers()
    entry = _CODE_CHECKS.get(rule_id)
    if not entry:
        return []
    func_name, exts, min_conf, _ = entry
    ext = rel_path.rsplit(".", 1)[-1].lower() if "." in rel_path else ""
    if ext not in exts:
        return []

    func = get_checker_func(func_name)
    if func is None:
        return []

    try:
        matches = func(content, rel_path)
        return [m for m in matches if m.get("confidence", 0) >= min_conf]
    except Exception:
        import logging
        logging.getLogger("kasra.scanner").debug("Checker %s failed", rule_id, exc_info=True)
        return []


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _pat(content: str, pattern: str, conf: float, tag: str) -> list[dict[str, Any]]:
    """Run a regex pattern and return match dicts."""
    results: list[dict[str, Any]] = []
    try:
        for m in re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE):
            results.append({"start": m.start(), "end": m.end(), "matched": m.group()[:200], "confidence": conf, "pattern": tag})
    except re.error:
        pass
    return results


def match_dockerfile(content: str, pattern: str, confidence: float) -> list[dict[str, Any]]:
    """Match Dockerfile instructions structurally. Pattern format: ``INSTRUCTION:value_regex``"""
    results: list[dict[str, Any]] = []
    if ":" not in pattern:
        return results
    instr, value_re = pattern.split(":", 1)
    instr = instr.strip().upper()
    for i, line in enumerate(content.split("\n")):
        stripped = line.strip()
        if not stripped.upper().startswith(instr):
            continue
        target = stripped[len(instr):].strip()
        try:
            if re.search(value_re, target, re.IGNORECASE):
                pos = sum(len(l) + 1 for l in content.split("\n")[:i])
                results.append({"start": pos, "end": pos + len(line), "matched": line.strip()[:200], "confidence": confidence, "pattern": pattern})
        except re.error:
            continue
    return results


def match_yaml_path(content: str, pattern: str, confidence: float) -> list[dict[str, Any]]:
    """Match YAML key paths with value regex. Pattern format: ``key.path:value_regex``"""
    results: list[dict[str, Any]] = []
    if ":" not in pattern:
        return results
    path_str, value_re = pattern.split(":", 1)
    keys = [k.strip() for k in path_str.split(".")]
    current_path: list[str] = []
    indent_stack: list[int] = []
    for i, line in enumerate(content.split("\n")):
        if not line.strip() or line.strip().startswith("#") or line.strip().startswith("---"):
            continue
        stripped = line.rstrip()
        indent = len(line) - len(line.lstrip())
        key_part = stripped.lstrip()
        if ":" in key_part:
            key = key_part.split(":", 1)[0].strip()
            value = key_part.split(":", 1)[1].strip().strip('"').strip("'") if ":" in key_part else ""
            while indent_stack and indent <= indent_stack[-1]:
                indent_stack.pop()
                if current_path:
                    current_path.pop()
                if indent_stack and indent <= indent_stack[-1]:
                    if current_path:
                        current_path.pop()
            indent_stack.append(indent)
            current_path.append(key)
            if current_path == keys:
                try:
                    if re.search(value_re, value, re.IGNORECASE):
                        pos = sum(len(l) + 1 for l in content.split("\n")[:i])
                        results.append({"start": pos, "end": pos + len(line), "matched": line.strip()[:200], "confidence": confidence, "pattern": pattern})
                except re.error:
                    continue
    return results


def match_keyvalue(content: str, pattern: str, confidence: float) -> list[dict[str, Any]]:
    """Match key=value pairs in config files. Pattern format: ``KEY:value_regex``"""
    results: list[dict[str, Any]] = []
    if ":" not in pattern:
        return results
    key_name, value_re = pattern.split(":", 1)
    for line in content.split("\n"):
        stripped = line.strip()
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
                    results.append({"start": max(0, content.find(line)), "end": content.find(line) + len(line), "matched": line.strip()[:200], "confidence": confidence, "pattern": pattern})
            except re.error:
                continue
    return results

















































































































































































































































































































































































