"""Code security checkers — pattern matching logic extracted from scanner.py.

Each checker is a module-level function ``(content, rel_path) -> list[dict]``.
"""

from __future__ import annotations

import json
import re
from pathlib import PurePosixPath
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
        "SEC-40": ("check_cve", ["json","txt","xml"], 0.5, "Known CVE dependencies"),
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


def _is_vulnerable(installed: str, vulnerable_range: str) -> bool:
    """Compare semver strings for CVE checking."""
    try:
        parts_i = [int(x) for x in installed.split(".")]
        limit_str = vulnerable_range.lstrip("<=> ")
        parts_l = [int(x) for x in limit_str.split(".")]
        while len(parts_i) < 3: parts_i.append(0)
        while len(parts_l) < 3: parts_l.append(0)
        for a, b in zip(parts_i, parts_l):
            if a != b:
                return a <= b if "<=" in vulnerable_range else a < b
        return "<=" in vulnerable_range
    except (ValueError, IndexError):
        return False


# ===================================================================
# Config-parsing engines
# ===================================================================

def match_dockerfile(content: str, pattern: str, confidence: float) -> list[dict[str, Any]]:
    """Dockerfile instruction parser. Pattern: ``INSTRUCTION:value_regex``."""
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
    """YAML key-path parser. Pattern: ``key.path:value_regex``."""
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
        indent = len(line) - len(line.lstrip())
        key_part = line.lstrip()
        if ":" not in key_part:
            continue
        key = key_part.split(":", 1)[0].strip()
        value = key_part.split(":", 1)[1].strip().strip('"').strip("'")
        while indent_stack and indent <= indent_stack[-1]:
            indent_stack.pop()
            if current_path: current_path.pop()
            if indent_stack and indent <= indent_stack[-1] and current_path: current_path.pop()
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
    """Key=value parser for .env/.properties. Pattern: ``KEY:value_regex``."""
    results: list[dict[str, Any]] = []
    if ":" not in pattern:
        return results
    key_name, value_re = pattern.split(":", 1)
    for line in content.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        sep = "=" if "=" in stripped else ":"
        parts = stripped.split(sep, 1)
        if len(parts) < 2:
            continue
        k, v = parts[0].strip(), parts[1].strip().strip('"').strip("'")
        if k.upper() == key_name.upper():
            try:
                if re.search(value_re, v, re.IGNORECASE):
                    pos = content.find(line)
                    results.append({"start": max(0, pos), "end": pos + len(line), "matched": line.strip()[:200], "confidence": confidence, "pattern": pattern})
            except re.error:
                continue
    return results


# ===================================================================
# Checker implementations
# ===================================================================

def check_sql_injection(content: str, rel_path: str) -> list[dict[str, Any]]:
    m = []
    for p, t in [
        (r"(?:cursor|execute|query|exec)\s*\(\s*(?:f['\"]|['\"][^'\"]*\+|\+ [^'\"]*['\"])", "execute concat"),
        (r"(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;]*\+\s*\w+", "SQL concat"),
        (r"(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{[^}]+\}", "SQL template"),
        (r"fmt\.Sprintf\s*\(\s*['\"](?:SELECT|INSERT|UPDATE|DELETE)", "Go Sprintf"),
        (r"SqlCommand\s*\(\s*['\"][^'\"]*\+", "C# SqlCommand"),
        (r"db\.(?:Exec|Query|QueryRow)\s*\([^)]*\+", "Go db concat"),
    ]:
        m.extend(_pat(content, p, 0.7, t))
    return m

def check_nosql(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"\$where\s*'?\s*:", 0.7, "$where") + \
           _pat(content, r"findByIdAnd(?:Update|Delete)\s*\(\s*\w+\s*,", 0.65, "Mongoose")

def check_os_command_injection(content: str, rel_path: str) -> list[dict[str, Any]]:
    m = []
    for p, c, t in [
        (r"subprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True", 0.7, "subprocess shell=True"),
        (r"exec\.Command\s*\(\s*['\"]sh['\"]\s*,\s*['\"]-c['\"]", 0.8, "Go sh -c"),
        (r"Runtime\.getRuntime\(\)\.exec\s*\([^)]*\+", 0.75, "Runtime.exec concat"),
        (r"shelL_exec\s*\(\s*['\"][^'\"]*\$\{?\w+", 0.7, "PHP shell_exec"),
    ]:
        try:
            for x in re.finditer(p, content, re.MULTILINE):
                m.append({"start":x.start(),"end":x.end(),"matched":x.group()[:200],"confidence":c,"pattern":t})
        except re.error: continue
    return m

def check_unsafe_deserialization(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?:pickle\.(?:loads|load)|shelve\.open)\s*\(", 0.85, "pickle") + \
           _pat(content, r"yaml\.(?:load|load_all)\s*\([^)]*(?:(?!SafeLoader|CSafeLoader).)", 0.8, "unsafe yaml") + \
           _pat(content, r"ObjectInputStream\.(?:readObject|readUnshared)\s*\(", 0.9, "Java deserialize") + \
           _pat(content, r"\bunserialize\s*\(\s*\$", 0.85, "PHP unserialize") + \
           _pat(content, r"Marshal\.(?:load|restore)\s*\(", 0.85, "Ruby marshal") + \
           _pat(content, r"XMLDecoder\s*\(", 0.85, "Java XMLDecoder")

def check_xxe(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"DocumentBuilderFactory\.newInstance\(\)(?![\s\S]*?setFeature.*disallow-doctype-dec)", 0.65, "Java XXE") + \
           _pat(content, r"new\s+XmlDocument\s*\([^)]*\)\s*\{[^}]*\bXmlResolver\s*=", 0.7, ".NET XXE") + \
           _pat(content, r"simplexml_load_string\s*\(", 0.6, "PHP XXE")

def check_ldap(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"['\"][^'\"]*\b(?:uid|cn|sn|mail)\s*=\s*['\"]\s*\+\s*\w+", 0.7, "LDAP") + \
           _pat(content, r"DirContext\.(?:search|lookup|list)\s*\(\s*['\"][^'\"]*\+\s*\w+", 0.75, "JNDI")

def check_ssti(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"render_template_string\s*\(\s*(?:f['\"]|['\"][^'\"]*\+|['\"][^'\"]*\{[^}]+\})", 0.75, "Flask SSTI") + \
           _pat(content, r"Handlebars\.compile\s*\(\s*\w+\s*\+", 0.65, "Handlebars") + \
           _pat(content, r"\$smarty->fetch\s*\(\s*['\"][^'\"]*\$", 0.7, "Smarty SSTI")

def check_header_injection(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"setHeader\s*\(\s*['\"][^'\"]*['\"]\s*,\s*\w+", 0.55, "header set")

def check_proto_pollution(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"_\.(?:merge|defaults|assign)\s*\([^)]*\b(?:body|input|query|param|user)", 0.65, "merge user") + \
           _pat(content, r"\[\s*['\"]__proto__['\"]\s*\]", 0.75, "__proto__")

def check_code_injection(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"\b(?:eval|exec)\s*\(\s*(?:req|request|input|user|data|body|query|params)", 0.85, "eval/exec") + \
           _pat(content, r"\bFunction\s*\(\s*(?:req|request|input|user|data)", 0.8, "Function()")

def check_xss(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"innerHTML\s*=\s*(?!['\"])\w+", 0.65, "innerHTML") + \
           _pat(content, r"dangerouslySetInnerHTML\s*=\s*\{*\s*__html", 0.75, "dangerously") + \
           _pat(content, r"v-html\s*=\s*['\"]?\s*\w+", 0.65, "v-html") + \
           _pat(content, r"document\.write\s*\(\s*\w+", 0.65, "document.write")

def check_csrf(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)@csrf\.exempt\b", 0.85, "CSRF exempt") + \
           _pat(content, r"(?i)csrf_exempt\b", 0.85, "csrf_exempt")

def check_auth_missing(content: str, rel_path: str) -> list[dict[str, Any]]:
    m = []
    for x in re.finditer(r"@(?:app\.(?:route|get|post|put|delete|patch)|csrf_exempt)\s*\(", content):
        chunk = content[x.end():x.end() + 500]
        if not re.search(r"@(?:login_required|jwt_required|permission_required|user_passes_test)", chunk):
            m.append({"start": x.start(), "end": x.end() + 30, "matched": x.group()[:200], "confidence": 0.4, "pattern": "no auth"})
    return m

def check_ssrf(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"requests\.(?:get|post|put|delete|patch|request)\s*\(\s*\w+", 0.6, "requests SSRF") + \
           _pat(content, r"axios\.(?:get|post|put|delete|patch|request)\s*\(\s*\w+", 0.6, "axios SSRF") + \
           _pat(content, r"fetch\s*\(\s*\w+", 0.55, "fetch SSRF")

def check_open_redirect(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"redirect\s*\(\s*(?:request|req)\.(?:GET|args|query|params)\.get\s*\(\s*['\"](?:next|url|redirect|return)['\"]", 0.7, "redirect")

def check_file_upload(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?:request\.files|request\.FILES|request->file|req\.file|upload)\s*\(?[^)]*\)?\.\s*(?:save|store|put|write)", 0.65, "file save")

def check_idor(content: str, rel_path: str) -> list[dict[str, Any]]:
    for m in re.finditer(r"(?:router|app)\.(?:get|post|put|delete|patch)\s*\(\s*['\"][^'\"]*[:<](\w+)[>'\"]", content):
        param, chunk = m.group(1), content[m.end():m.end() + 500]
        if re.search(rf"(?:find|query|get|where|filter)\s*\([^)]*{param}", chunk, re.IGNORECASE) and \
           not re.search(r"(?:owner|user_id|current_user|req\.user|userId|permission)", chunk, re.IGNORECASE):
            return [{"start": m.start(), "end": m.end() + 30, "matched": m.group()[:200], "confidence": 0.4, "pattern": "idor"}]
    return []

def check_file_inclusion(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", 0.85, "PHP include") + \
           _pat(content, r"fs\.readFile\s*\(\s*\w+(?:input|user|param|query|path|file)?\b", 0.6, "fs.readFile")

def check_mass_assignment(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?:User|Model|Entity)\.(?:create|update|save)\s*\(\s*(?:req|request)\.(?:body|params|data|json)", 0.65, "mass assign") + \
           _pat(content, r"\w+\.(?:create|build|assign_attributes)\s*\(\s*(?:params|request_params)", 0.6, "Rails mass assign")

def check_jwt(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"['\"]alg['\"]\s*:\s*['\"]none['\"]", 0.9, "alg=none") + \
           _pat(content, r"(?i)algorithm\s*=\s*['\"]none['\"]", 0.9, "alg=none kwarg") + \
           _pat(content, r"(?i)\bJWT_SECRET\s*[:=]\s*['\"](?:secret|changeme|password)['\"]", 0.8, "weak secret")

def check_session_defects(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)session_cookie_secure\s*[:=]\s*(?:False|false)", 0.7, "not secure")

def check_oauth(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)response_type\s*['\"]token['\"]", 0.7, "implicit flow")

def check_websocket(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"new\s+WebSocket\s*\(\s*['\"]ws://", 0.75, "insecure ws")

def check_grpc(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)insecure\.NewCredentials\(\)", 0.85, "gRPC insecure") + \
           _pat(content, r"(?i)WithInsecure\s*\(", 0.8, "WithInsecure")

def check_graphql(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)(?:introspection)\s*[:=]\s*true", 0.7, "introspection")

def check_weak_crypto(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)\bhashlib\.md5\b|\bMessageDigest\.getInstance\s*\(\s*['\"]MD5", 0.85, "MD5") + \
           _pat(content, r"(?i)\bhashlib\.sha1\b|\bMessageDigest\.getInstance\s*\(\s*['\"]SHA-?1", 0.85, "SHA1")

def check_insecure_random(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"^import random$|^from random import", 0.75, "import random") + \
           _pat(content, r"Math\.random\s*\(\s*\)", 0.7, "Math.random")

def check_tls_disabled(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"verify\s*=\s*(?:False|false|0)", 0.8, "verify=False") + \
           _pat(content, r"InsecureSkipVerify\s*[:=]\s*(?:true|True)", 0.85, "InsecureSkipVerify") + \
           _pat(content, r"rejectUnauthorized\s*[:=]\s*(?:false|0)", 0.85, "rejectUnauthorized")

def check_insecure_cert(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)ALLOW_ALL_HOSTNAME_VERIFIER", 0.85, "allow all")

def check_dep_confusion(content: str, rel_path: str) -> list[dict[str, Any]]:
    m = []
    bname = PurePosixPath(rel_path).name
    if bname in ("package.json", "package-lock.json"):
        try:
            pkgs = json.loads(content)
            deps = {**(pkgs.get("dependencies", {}) or {}), **(pkgs.get("devDependencies", {}) or {})}
            for pkg, ver in deps.items():
                if not isinstance(ver, str): continue
                if ver in ("*", "") or ver.startswith("file:") or ver.startswith("http:"):
                    pos = content.find(f'"{pkg}"') if f'"{pkg}"' in content else 0
                    m.append({"start": max(0, pos), "end": 0, "matched": f"{pkg}@{ver}", "confidence": 0.5, "pattern": "dep confusion"})
        except Exception: pass
    elif bname in ("requirements.txt", "Pipfile"):
        common = {"django","flask","requests","numpy","pandas","pytest","fastapi"}
        for x in re.finditer(r"^([a-zA-Z_][a-zA-Z0-9_.-]*)[=~<>!]", content, re.MULTILINE):
            pkg = x.group(1).lower()
            if pkg not in common and not pkg.startswith("_"):
                m.append({"start": x.start(), "end": x.end(), "matched": pkg, "confidence": 0.35, "pattern": "dep confusion"})
    return m

def check_observability_leak(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)/actuator", 0.5, "actuator") + \
           _pat(content, r"(?i)/metrics", 0.4, "metrics")

def check_path_traversal(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"os\.path\.join\s*\([^)]*\w+(?:input|user|file|name|path|filename)?\b\s*,", 0.55, "os.path.join") + \
           _pat(content, r"Path\.Combine\s*\([^)]*\w+(?:input|user|file|name|path|fileName)?\b", 0.6, "Path.Combine") + \
           _pat(content, r"(?:file_get_contents|unlink|fopen)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", 0.8, "PHP file op")

def check_race_condition(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)if\s+os\.path\.exists\b", 0.4, "TOCTOU")

def check_resource_exhaustion(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"while\s+True\s*:", 0.5, "infinite loop")

def check_zip_slip(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?:zipfile|tarfile)\.(?:extractall|extract)\s*\(", 0.7, "archive extract")

def check_memory_safety(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"\bgets\s*\(", 0.85, "gets") + \
           _pat(content, r"\bstrcpy\s*\(", 0.75, "strcpy")

def check_error_leak(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"traceback\.format_exc\s*\(", 0.75, "traceback") + \
           _pat(content, r"err\.stack", 0.65, "err.stack")

def check_command_exec(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"os\.system\s*\(", 0.85, "os.system") + \
           _pat(content, r"subprocess\.(?:call|Popen|run)\s*\(", 0.75, "subprocess") + \
           _pat(content, r"Runtime\.getRuntime\(\)\.exec\s*\(", 0.85, "Runtime.exec") + \
           _pat(content, r"child_process\.(?:exec|execSync|spawn)\s*\(", 0.8, "child_process") + \
           _pat(content, r"Process\.Start\s*\([^)]*['\"](?:cmd|bash|sh|powershell)", 0.8, "Process.Start")

def check_log_injection(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"logging\.(?:info|debug|error|warning)\s*\(\s*(?:f['\"]|['\"][^'\"]*\+\s*\w+)", 0.55, "log concat")

def check_integer_overflow(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?:balance|amount|total|count|quantity|credits?)\s*-=\s*\w+", 0.45, "balance sub")

def check_null_deref(content: str, rel_path: str) -> list[dict[str, Any]]:
    m = []
    for i, line in enumerate(content.split("\n")):
        for x in re.finditer(r"(?:\.find(?:ById|One|First|All)?|\.getOrNull|Optional\.ofNullable|FirstOrDefault)\s*\([^)]*\)", line):
            if i + 1 < len(content.split("\n")) and re.search(r"\.\s*\w+\s*\(", content.split("\n")[i + 1]):
                if not re.search(r"\bisPresent\b|orElse\b|orElseThrow\b|!= null|!= nil", line + "\n" + content.split("\n")[i + 1]):
                    pos = sum(len(l) + 1 for l in content.split("\n")[:i])
                    m.append({"start": pos, "end": pos + len(line), "matched": line[:200], "confidence": 0.4, "pattern": "null deref"})
    return m

def check_plaintext_password(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)(?:INSERT\s+INTO\s+\w+\s*\([^)]*password[^)]*\))", 0.55, "password insert") + \
           _pat(content, r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{3,}['\"]", 0.5, "password assign")

def check_weak_password_policy(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)(?:min[_\.]?(?:length|len|size)|minLength)\s*[:=<>!]+\s*([456])\b", 0.65, "min length")

def check_audit_log_missing(content: str, rel_path: str) -> list[dict[str, Any]]:
    m = []
    for x in re.finditer(r"(?i)(?:DELETE|UPDATE)\s+(?:FROM\s+)?(?:users?|accounts?|transactions?|employees?)\s+WHERE", content):
        if not re.search(r"(?i)(?:audit|log|record)", content[x.end():x.end() + 300]):
            m.append({"start": x.start(), "end": x.end(), "matched": x.group()[:200], "confidence": 0.5, "pattern": "no audit log"})
    return m

def check_brute_force(content: str, rel_path: str) -> list[dict[str, Any]]:
    m = []
    for x in re.finditer(r"(?i)(?:def\s+login|def\s+signin|function\s+login)\s*\(", content):
        if not re.search(r"(?i)(?:rate.?limit|throttle|lockout|fail.?count|max.?attempt|captcha)", content[x.end():x.end() + 500]):
            m.append({"start": x.start(), "end": x.end(), "matched": x.group()[:200], "confidence": 0.45, "pattern": "no rate limit"})
    return m

def check_insecure_deletion(content: str, rel_path: str) -> list[dict[str, Any]]:
    m = []
    for x in re.finditer(r"(?i)(?:is_deleted\s*=\s*True|deleted_at\s*=)", content):
        if not re.search(r"(?i)(?:cleanup|purge|vacuum|physical.?delete|hard.?delete|archive)", content[max(0, x.start() - 200):x.end() + 300]):
            m.append({"start": x.start(), "end": x.end(), "matched": x.group()[:200], "confidence": 0.5, "pattern": "soft delete"})
    return m

def check_webview(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)setJavaScriptEnabled\s*\(\s*true\s*\)", 0.75, "JS enabled")

def check_mobile_storage(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)SharedPreferences\.(?:putString|getString)\s*\(\s*['\"](?:token|password|secret|api_key)", 0.7, "SharedPrefs")

def check_deep_link(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"android:exported\s*=\s*\"true\"", 0.5, "exported")

def check_cert_pinning(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)CertificatePinner|ServerTrustManager|ssl.?pinning", 0.5, "pinning")

def check_clipboard(content: str, rel_path: str) -> list[dict[str, Any]]:
    return _pat(content, r"(?i)ClipboardManager|UIPasteboard|Clipboard\.setData", 0.55, "clipboard")

def check_cve(content: str, rel_path: str) -> list[dict[str, Any]]:
    """Check dependencies against known CVE database."""
    matches_list: list[dict[str, Any]] = []
    try:
        from kasra.utils.package import find_data_dir
        cve_path = find_data_dir("rules") / "_cve-data.json"
        if not cve_path.exists():
            return matches_list
        with open(cve_path) as f:
            cve_db = json.load(f)
    except (OSError, json.JSONDecodeError):
        return matches_list
    entries = cve_db.get("entries", [])
    if not entries:
        return matches_list
    bname = PurePosixPath(rel_path).name
    if bname in ("package.json", "package-lock.json"):
        try:
            pkgs = json.loads(content)
            deps = {**(pkgs.get("dependencies", {}) or {}), **(pkgs.get("devDependencies", {}) or {})}
            for pkg, ver in deps.items():
                if not isinstance(ver, str): continue
                cleaned = ver.lstrip("^~>=<! ")
                for e in entries:
                    if e["package"].lower() == pkg.lower() and _is_vulnerable(cleaned, e["vulnerable"]):
                        pos = content.find(f'"{pkg}"') if f'"{pkg}"' in content else 0
                        matches_list.append({"start": max(0, pos), "end": 0, "matched": f"{pkg}@{ver}", "confidence": 0.75, "pattern": e["cve"]})
        except Exception: pass
    elif bname in ("requirements.txt", "Pipfile"):
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"): continue
            for e in entries:
                if e["package"].lower() in line.lower():
                    m = re.search(r"([\d.]+)", line)
                    if m and _is_vulnerable(m.group(1), e["vulnerable"]):
                        pos = content.find(line)
                        matches_list.append({"start": max(0, pos), "end": pos + len(line), "matched": line[:200], "confidence": 0.75, "pattern": e["cve"]})
    elif bname in ("pom.xml", "build.gradle"):
        for e in entries:
            pkg = e["package"].lower()
            if pkg in content.lower():
                for m in re.finditer(r"<version>([\d.]+)</version>", content, re.IGNORECASE):
                    if _is_vulnerable(m.group(1), e["vulnerable"]):
                        if not any(a["pattern"] == e["cve"] for a in matches_list):
                            matches_list.append({"start": m.start(), "end": m.end(), "matched": m.group()[:200], "confidence": 0.75, "pattern": e["cve"]})
    return matches_list
