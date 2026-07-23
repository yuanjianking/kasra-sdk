"""Kasra O-series Python code checkers.

Each checker is a function ``(content: str) -> list[dict]`` that returns
match dicts with keys ``start``, ``end``, ``matched``, ``confidence``, ``pattern``.

These run inside ``RuleRunner.run_rule()`` **in addition to** the regex/keyword
matchers when a rule has a Python checker registered.
"""

from __future__ import annotations

import re
from typing import Any

# Registry: rule_id -> checker_function
_CHECKERS: dict[str, callable] = {}


def register(rule_id: str):
    """Decorator to register a checker for a rule ID."""
    def wrapper(func):
        _CHECKERS[rule_id] = func
        return func
    return wrapper


def get_checker(rule_id: str) -> callable | None:
    """Return the checker for *rule_id*, or None."""
    return _CHECKERS.get(rule_id)


def has_checker(rule_id: str) -> bool:
    return rule_id in _CHECKERS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _match(content: str, pattern: str, base_confidence: float, tag: str) -> list[dict[str, Any]]:
    """Run a regex and return match dicts with context-adjusted confidence."""
    results: list[dict[str, Any]] = []
    try:
        for m in re.finditer(pattern, content, re.MULTILINE):
            adj = _adjust_confidence(content, m.start(), base_confidence)
            if adj <= 0:
                continue
            results.append({
                "start": m.start(),
                "end": m.end(),
                "matched": m.group()[:200],
                "confidence": adj,
                "pattern": tag,
            })
    except re.error:
        pass
    return results


def _adjust_confidence(content: str, pos: int, base: float) -> float:
    """Adjust confidence up/down based on context around *pos*.

    - Inside a comment → drop by 0.2 (likely safe example)
    - Inside a test function → drop by 0.1 (test code)
    - Inside an f-string/docstring → drop by 0.15 (example code)
    - Has ``# nosemgrep`` or ``# skip`` nearby → drop to 0.0
    - Variable name contains ``safe``/``example``/``sample`` nearby → drop by 0.1
    """
    window = content[max(0, pos - 200):pos + 100].lower()

    # nosemgrep/skip → skip entirely
    if re.search(r"#\s*(?:nosemgrep|skip|no.check|ignore)\b", window):
        return 0.0

    # Inside comment → likely illustrative
    if re.search(r"#.*$|//.*$|/\*.*\*/$|<!--.*-->$", window, re.MULTILINE):
        return max(base - 0.2, 0.1)

    # Inside test
    if re.search(r"(?:def test_|class Test|@pytest)", window):
        return max(base - 0.1, 0.1)

    # Example/sample code
    if re.search(r"\b(?:example|sample|illustrative|demo)\b", window):
        return max(base - 0.15, 0.1)

    # Safe variable names
    if re.search(r"\b(?:safe|harmless|benign|playground|mock)\b", window):
        return max(base - 0.15, 0.1)

    return base


# ===================================================================
# O-01 ~ O-17 checkers — enhanced with context-aware confidence
# ===================================================================

@register("O-01")
def check_dangerous_function_call(content: str) -> list[dict[str, Any]]:
    """Detect dangerous function calls (eval, exec, system, etc.)."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"\b(?:eval|exec)\s*\(", 0.8, "eval/exec"),
        (r"\b(?:system|popen|__import__)\s*\(", 0.8, "system/popen"),
        (r"subprocess\.(?:call|Popen|run)\s*\(", 0.85, "subprocess"),
        (r"Runtime\.getRuntime\(\)\.exec\s*\(", 0.85, "Runtime.exec"),
        (r"new\s+ProcessBuilder\s*\(", 0.75, "ProcessBuilder"),
        (r"Class\.forName\s*\(", 0.6, "Class.forName"),
        (r"Process\.Start\s*\(", 0.85, "Process.Start"),
        (r"exec\.Command\s*\(", 0.85, "exec.Command"),
        (r"os\.StartProcess\s*\(", 0.7, "os.StartProcess"),
        (r"syscall\.Exec\s*\(", 0.8, "syscall.Exec"),
        (r"(?:shell_exec|exec|system)\s*\(\s*\$", 0.7, "PHP exec"),
        (r"create_function\s*\(", 0.7, "PHP create_function"),
        (r"popen\s*\(\s*\$", 0.7, "PHP popen"),
        (r"std::process::Command", 0.85, "Rust Command"),
        (r"Command::new\s*\(\s*['\"]sh['\"]", 0.8, "Rust shell"),
        (r"new\s+Function\s*\(\s*['\"]", 0.8, "JS Function()"),
        (r"child_process\.(?:exec|execSync|spawn|fork)\s*\(", 0.8, "child_process"),
        (r"`[^`]*\#\{?\w+[^`]*`", 0.7, "ruby backtick"),
        (r"%x\([^)]*", 0.65, "ruby %x()"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-02")
def check_dangerous_shell_command(content: str) -> list[dict[str, Any]]:
    """Detect destructive shell commands."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"rm\s+(?:-rf|\/|\-rf\s+\/|\-rf\s+\/\*)", 0.9, "rm -rf"),
        (r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", 0.95, "fork bomb"),
        (r"dd\s+if=\s*\/dev\/zero\s+of=\s*\/dev\/sd", 0.9, "dd overwrite"),
        (r"\bmkfs\.\w+\s+\/dev\/", 0.85, "mkfs"),
        (r"chmod\s+-R\s+777\s+\/", 0.9, "chmod -R 777 /"),
        (r"mv\s+\/\s+\/dev\/null", 0.9, "mv / to null"),
        (r"shutdown\s+(?:\-h\s+now|\-r\s+now|/s)", 0.7, "shutdown"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-03")
def check_os_command_injection(content: str) -> list[dict[str, Any]]:
    """Detect OS command injection."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"subprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True", 0.75, "subprocess shell=True"),
        (r"exec\.Command\s*\(\s*['\"]sh['\"]\s*,\s*['\"]-c['\"]\s*,", 0.8, "go sh -c"),
        (r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[\"'](?:(?:ping|nslookup)\s+[\"']\s*\+\s*\w+", 0.75, "Runtime.exec concat"),
        (r"`[^`]*\#\{?\w+[^`]*`", 0.65, "backtick interpolation"),
        (r"shell_exec\s*\(\s*['\"][^'\"]*\$\{?\w+", 0.7, "PHP shell_exec"),
        (r"\bexec\s*\(\s*['\"][^'\"]+\+[^'\"]+['\"]\s*\)", 0.7, "exec concat"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-04")
def check_sql_injection(content: str) -> list[dict[str, Any]]:
    """Detect SQL injection in generated code."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"cursor\.execute\s*\(\s*(?:f['\"]|['\"][^'\"]*\+|['\"][^'\"]*\{[^}]+\})", 0.7, "execute concat/fstring"),
        (r"(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^;]*\+\s*\w+", 0.7, "SQL concat"),
        (r"fmt\.Sprintf\s*\(\s*['\"](?:SELECT|INSERT|UPDATE|DELETE)", 0.75, "Go fmt.Sprintf"),
        (r"\b(?:query|sql)\s*(?::|=)\s*['\"][^'\"]*\{[^}]+\}", 0.6, "template string SQL"),
        (r"new\s+Statement\s*\(|createStatement\s*\(.*\+", 0.65, "Java Statement"),
        (r"SqlCommand\s*\(\s*['\"][^'\"]*\+", 0.65, "C# SqlCommand"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-05")
def check_nosql_injection(content: str) -> list[dict[str, Any]]:
    """Detect NoSQL injection."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"\$where\s*[:=]\s*['\"][^'\"]*\{?\w+", 0.7, "$where injection"),
        (r"find\s*\(\s*\{[^}]*\$where", 0.7, "find $where"),
        (r"N1QLQuery\s*\(\s*['\"][^'\"]*\+", 0.7, "N1QL concat"),
        (r"findByIdAnd(?:Update|Delete)\s*\(\s*\w+\s*,", 0.65, "Mongoose injection"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-06")
def check_empty_exception_handler(content: str) -> list[dict[str, Any]]:
    """Detect empty exception handlers."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"except\s*(?:[A-Za-z_]\w*)?\s*:\s*\n\s*pass\b", 0.8, "except: pass"),
        (r"catch\s*\(\s*(?:_|[A-Za-z_]\w*(?:\s+\w+)?)\s*\)\s*\{\s*\}", 0.8, "empty catch"),
        (r"if\s+err\s+!=\s+nil\s*\{\s*\n\s*return\b", 0.6, "Go err ignore"),
        (r"\/\/\s*(?:swallow|ignore|silently|nothing)\s*(?:error|exception)?", 0.7, "swallow comment"),
        (r"catch\s+\{\s*\}", 0.8, "C# empty catch"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-07")
def check_insecure_randomness(content: str) -> list[dict[str, Any]]:
    """Detect insecure RNG in security-sensitive contexts."""
    results: list[dict[str, Any]] = []
    is_sensitive = any(kw in content.lower() for kw in
                       ["token", "password", "secret", "session", "csrf", "jwt", "key", "hash"])
    if not is_sensitive:
        return results
    patterns = [
        (r"^import random$|^from random import", 0.75, "import random"),
        (r"\brand\s*\(\s*\)|\bmt_rand\s*\(\s*\)", 0.7, "rand()"),
        (r"Math\.random\s*\(\s*\)", 0.7, "Math.random"),
        (r"java\.util\.Random\b", 0.8, "java.util.Random"),
        (r"new\s+Random\s*\(\s*\)", 0.65, "new Random"),
        (r"math/rand\"", 0.7, "Go math/rand"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-08")
def check_xxe(content: str) -> list[dict[str, Any]]:
    """Detect XXE-vulnerable XML parsers."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"DocumentBuilderFactory\.newInstance\(\)(?![\s\S]*?setFeature.*disallow-doctype-dec)", 0.65, "Java XXE"),
        (r"new\s+XmlDocument\s*\([^)]*\)\s*\{[^}]*\bXmlResolver\s*=", 0.7, ".NET XXE"),
        (r"simplexml_load_string\s*\(", 0.6, "PHP simplexml"),
        (r"xml\.Decoder\s*\{[^}]*\bStrict\s*=\s*false", 0.7, "Go XXE"),
        (r"lxml\.(?:fromstring|parse|XML)\s*\([^)]*\bresolve_entities\s*(?!=\s*False)", 0.65, "Python lxml"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-09")
def check_ssti(content: str) -> list[dict[str, Any]]:
    """Detect SSTI patterns."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"render_template_string\s*\(\s*(?:f['\"]|['\"][^'\"]*\+|['\"][^'\"]*\{[^}]+\})", 0.75, "Flask SSTI"),
        (r"Template\s*\(\s*['\"][^'\"]*\+[^'\"]+['\"]\s*\)\s*\.render", 0.7, "Python Template"),
        (r"Handlebars\.compile\s*\(\s*\w+\s*\+", 0.65, "Handlebars compile"),
        (r"\$smarty->fetch\s*\(\s*['\"][^'\"]*\$", 0.7, "Smarty SSTI"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-10")
def check_ldap_injection(content: str) -> list[dict[str, Any]]:
    """Detect LDAP injection."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"['\"][^'\"]*\b(?:uid|cn|sn|mail)\s*=\s*['\"]\s*\+\s*\w+", 0.7, "filter concat"),
        (r"DirContext\.(?:search|lookup|list)\s*\(\s*['\"][^'\"]*\+\s*\w+", 0.75, "JNDI search"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-11")
def check_unsafe_deserialization(content: str) -> list[dict[str, Any]]:
    """Detect unsafe deserialization."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"(?:pickle\.(?:loads|load)|shelve\.open)\s*\(", 0.85, "pickle"),
        (r"yaml\.(?:load|load_all)\s*\([^)]*(?:(?!SafeLoader|CSafeLoader).)", 0.8, "unsafe yaml"),
        (r"ObjectInputStream\.(?:readObject|readUnshared)\s*\(", 0.9, "Java deserialize"),
        (r"\bunserialize\s*\(\s*\$", 0.85, "PHP unserialize"),
        (r"Marshal\.(?:load|restore)\s*\(", 0.85, "Ruby marshal"),
        (r"new\s+BinaryFormatter\s*\([^)]*\).*\.Deserialize\s*\(", 0.85, ".NET BinaryFormatter"),
        (r"XMLDecoder\s*\(", 0.85, "Java XMLDecoder"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-12")
def check_ssrf(content: str) -> list[dict[str, Any]]:
    """Detect SSRF with user-controlled URLs."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"requests\.(?:get|post|put|delete|patch|request)\s*\(\s*\w+(?:url|input|user|param|query|body|data|host|endpoint)?\b", 0.6, "requests SSRF"),
        (r"axios\.(?:get|post|put|delete|patch|request)\s*\(\s*\w+(?:url|input|user|param|query|body|data)?\b", 0.6, "axios SSRF"),
        (r"fetch\s*\(\s*\w+(?:url|input|user|param|query|body|data)?\b", 0.55, "fetch SSRF"),
        (r"HttpClient\.(?:execute|SendAsync)\s*\(\s*\w+", 0.6, "HttpClient"),
        (r"http\.(?:Get|Post|NewRequest)\s*\(\s*\w+", 0.55, "Go HTTP"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-13")
def check_certificate_validation_disabled(content: str) -> list[dict[str, Any]]:
    """Detect disabled TLS cert validation."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"verify\s*=\s*(?:False|false|0)", 0.8, "verify=False"),
        (r"check_hostname\s*=\s*(?:False|false)", 0.8, "check_hostname=False"),
        (r"rejectUnauthorized\s*[:=]\s*(?:false|0)", 0.85, "rejectUnauthorized"),
        (r"InsecureSkipVerify\s*[:=]\s*(?:true|True)", 0.85, "InsecureSkipVerify"),
        (r"ServerCertificateValidationCallback\s*[:=]\s*\{[^}]*true\s*\}", 0.85, "callback=true"),
        (r"(?i)VERIFY_NONE", 0.85, "VERIFY_NONE"),
        (r"(?i)trustAllCertificates|trust_all_certs", 0.85, "trust all"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-14")
def check_prototype_pollution(content: str) -> list[dict[str, Any]]:
    """Detect prototype pollution in JS/TS."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"_\.(?:merge|defaults|assign)\s*\([^)]*\b(?:body|input|query|param|user|data)", 0.65, "merge user input"),
        (r"Object\.(?:assign|create)\s*\([^)]*\b(?:body|input|query|param|user|data)", 0.6, "Object.assign"),
        (r"\[\s*['\"]__proto__['\"]\s*\]", 0.75, "__proto__"),
        (r"\b__proto__\b", 0.65, "__proto__"),
        (r"\[\s*['\"]constructor['\"]\s*\]\s*\[\s*['\"]prototype['\"]\s*\]", 0.75, "constructor.prototype"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-15")
def check_path_traversal(content: str) -> list[dict[str, Any]]:
    """Detect path traversal."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"(?:open|os\.path\.join)\s*\([^)]*\w+(?:input|user|file|name|path|filename)?\b", 0.55, "unsafe path"),
        (r"Path\.Combine\s*\([^)]*\w+(?:input|user|file|name|path|fileName)?\b", 0.6, "Path.Combine"),
        (r"(?:file_get_contents|unlink|fopen)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)", 0.8, "PHP file op"),
        (r"new\s+File\s*\(\s*\w+(?:input|user|file|name|path|fileName)?\b", 0.5, "new File"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-16")
def check_redos(content: str) -> list[dict[str, Any]]:
    """Detect ReDoS-vulnerable regex (nested quantifiers)."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"\([^()]+\+\)\+", 0.65, "nested +"),
        (r"\([^()]+\+\)\*", 0.65, "nested +*"),
        (r"\([^()]+\*\)\+", 0.65, "nested *+"),
        (r"\([^()]+\*\)\*", 0.65, "nested **"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


@register("O-17")
def check_csrf_xss(content: str) -> list[dict[str, Any]]:
    """Detect CSRF/XSS in frontend code."""
    results: list[dict[str, Any]] = []
    patterns = [
        (r"innerHTML\s*=\s*\w+", 0.65, "innerHTML"),
        (r"outerHTML\s*=\s*\w+", 0.65, "outerHTML"),
        (r"document\.write\s*\(\s*\w+", 0.65, "document.write"),
        (r"dangerouslySetInnerHTML\s*=\s*\{?\s*__html", 0.75, "React dangerouslySetInnerHTML"),
        (r"v-html\s*=\s*['\"]?\s*\w+", 0.65, "Vue v-html"),
        (r"href\s*=\s*['\"][\s]*javascript:", 0.85, "javascript: href"),
        (r"window\.location\s*=\s*\w+(?:input|user|param|query|data)", 0.65, "window.location injection"),
    ]
    for pat, conf, tag in patterns:
        results.extend(_match(content, pat, conf, tag))
    return results


# ===================================================================
# I-series checkers (input detection via Python logic)
# ===================================================================

@register("I-43")
def check_oversized_input(content: str) -> list[dict[str, Any]]:
    """Detect oversized input exceeding 100,000 characters.
    Triggers truncation action when content exceeds the threshold.
    """
    threshold = 100000
    if len(content) > threshold:
        return [{
            "start": 0,
            "end": min(len(content), 200),
            "matched": f"Content length {len(content)} exceeds {threshold} character limit",
            "confidence": 1.0,
            "pattern": "oversized_input",
        }]
    return []


@register("I-48")
def check_context_reset(content: str) -> list[dict[str, Any]]:
    """Detect context reset bypass attempts.
    Catches multi-phrase reset attempts in Chinese.
    """
    results: list[dict[str, Any]] = []
    patterns = [
        (r"(?:忘记|清除|清空|重置|忽略|忽略掉|删除|移除|丢弃)\s*(?:所有|全部|之前|过去的|以前的)\s*(?:对话|聊天|历史|记录|记忆|内容|上下文|context)", 0.6),
        (r"(?:重新开始|新对话|新会话|新聊天|重新会话)\s*(?:对话|聊天|session|conversation)?", 0.5),
        (r"(?:不要|不需要|不用|别)\s*(?:记忆|记住|记得|上下文|历史|之前)", 0.5),
    ]
    for pat, conf in patterns:
        try:
            for m in re.finditer(pat, content, re.IGNORECASE):
                results.append({
                    "start": m.start(), "end": m.end(),
                    "matched": m.group()[:200], "confidence": conf,
                    "pattern": "context_reset_chinese",
                })
        except re.error:
            pass
    return results
