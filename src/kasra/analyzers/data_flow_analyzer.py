"""Kasra L3 Rule Engine — Basic data-flow analysis.

Layer 3 semantic analyzer that tracks variable origins through code
to determine whether dangerous function arguments are user-controlled
or hardcoded constants.

This is a **best-effort static analysis** that uses regex-based pattern
matching on source code — it is not a full AST-based data-flow framework.

Detection priorities
--------------------
1. **User-controlled sources**: ``request.args``, ``input()``, ``$_GET``,
   ``req.body``, ``argv``, environment variables.
2. **Assignment tracking**: ``x = user_input`` → ``x`` is tainted.
3. **Function argument tracing**: ``dangerous(x)`` → tainted argument.
4. **Sanitisation detection**: ``escape(x)``, ``realpath(x)`` → untaints.

Confidence levels
-----------------
  - ``1.0`` — analysis is certain (direct user input → dangerous call)
  - ``0.6`` — analysis is likely (assignment chain traced)
  - ``0.3`` — possible but weak signal (generic variable passed)
  - ``0.0`` — hardcoded constant (safe)
"""

from __future__ import annotations

import re
from collections import OrderedDict
from typing import Any

from kasra.analyzers.base import Analyzer
from kasra.analyzers.context import AnalysisContext


# Sources of user-controlled data, keyed by language
_USER_SOURCES: dict[str, list[str]] = {
    "python": [
        "input()", "sys.stdin", "sys.argv", "os.environ",
        "request.args", "request.form", "request.json", "request.data",
        "request.query", "request.params", "req.args", "req.form",
        "request.GET", "request.POST", "request.COOKIES",
        "flask.request", "fastapi.Request",
    ],
    "javascript": [
        "req.body", "req.query", "req.params", "req.headers",
        "request.body", "request.query", "request.params",
        "event.body", "event.query", "event.params",
        "process.argv", "process.env", "location.search",
        "window.location", "document.cookie",
        "req.url", "request.url", "ctx.request",
    ],
    "typescript": [
        "req.body", "req.query", "req.params", "request.body",
        "event.body", "event.query", "event.params",
        "process.argv", "process.env",
    ],
    "java": [
        "request.getParameter(", "request.getQueryString(",
        "request.getHeader(", "request.getCookies(",
        "HttpServletRequest", "@RequestParam", "@PathVariable",
        "System.getenv(", "args[", "System.in",
    ],
    "go": [
        "r.URL.Query()", "r.FormValue(", "r.PostFormValue(",
        "c.Query(", "c.Param(", "c.PostForm(",
        "os.Args", "os.Getenv(", "r.Body",
        "http.Handler", "gin.Context",
    ],
    "php": [
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE",
        "$_SERVER", "$_FILES", "$_ENV",
        "$argv", "php://input", "getenv(",
    ],
    "ruby": [
        "params[", "request.params", "request.query",
        "request.body", "cookies[", "ENV[",
        "ARGV", "STDIN",
    ],
    "cpp": [
        "getenv(", "argv[", "cin >>", "getchar(",
        "getcwd(", "readlink(",
    ],
    "csharp": [
        "Request.QueryString", "Request.Form", "Request.Params",
        "Request.Headers", "Request.Cookies",
        "Console.ReadLine(", "Environment.GetEnvironmentVariable(",
        "args[",
    ],
}

# Known sanitisation functions per language
_SANITISERS: dict[str, list[str]] = {
    "python": ["escape(", "sanitize(", "clean(", "validate(", "realpath(", "os.path.realpath(", "path.resolve(", "shlex.quote(", "pipes.quote("],
    "javascript": ["escape(", "sanitize(", "encodeURI(", "encodeURIComponent(", "DOMPurify.sanitize("],
    "typescript": ["escape(", "sanitize(", "encodeURI(", "encodeURIComponent("],
    "java": ["escape(", "sanitize(", "URLEncoder.encode(", "HtmlUtils.htmlEscape(", "StringEscapeUtils."],
    "go": ["url.QueryEscape(", "html.EscapeString(", "path.Clean(", "filepath.Clean(", "sanitize("],
    "php": ["htmlspecialchars(", "htmlentities(", "strip_tags(", "filter_input(", "escapeshellarg(", "realpath("],
    "ruby": ["escape(", "sanitize(", "Shellwords.escape("],
    "rust": ["shlex::quote(", "sanitize("],
}

# Dangerous sink functions and their argument indices (0-based) to check
_SINKS: dict[str, list[tuple[str, int]]] = {
    "python": [
        ("subprocess.call", 0), ("subprocess.Popen", 0), ("subprocess.run", 0),
        ("os.system", 0), ("os.popen", 0), ("eval(", 0), ("exec(", 0),
        ("__import__", 0), ("open(", 0),
        ("cursor.execute", 0), ("execute(", 0),
        ("requests.get", 0), ("requests.post", 0),
    ],
    "javascript": [
        ("eval(", 0), ("Function(", 0), ("setTimeout(", 0),
        ("exec(", 0), ("spawn(", 0),
        ("fetch(", 0), ("axios.get", 0), ("axios.post", 0),
        ("document.write", 0), ("innerHTML", 0),
    ],
    "java": [
        ("Runtime.getRuntime().exec", 0),
        ("ProcessBuilder(", 0),
        ("Statement.executeQuery", 0),
        ("Statement.executeUpdate", 0),
        ("DriverManager.getConnection", 0),
        ("Class.forName", 0),
    ],
    "go": [
        ("exec.Command", 0),
        ("http.Get", 0), ("http.Post", 0),
        ("sql.Query", 0), ("sql.QueryRow", 0),
        ("db.Query", 0), ("db.Exec", 0),
    ],
    "php": [
        ("shell_exec(", 0), ("exec(", 0), ("system(", 0),
        ("popen(", 0), ("mysqli_query(", 0),
        ("file_get_contents(", 0), ("curl_exec(", 0),
    ],
    "javascript": [
        ("exec(", 0), ("spawn(", 0),
        ("eval(", 0), ("Function(", 0),
        ("fetch(", 0), ("axios.get", 0),
        ("document.write", 0),
        ("innerHTML =", 0), ("innerHTML=", 0),
        ("mysql.query", 0), ("query(", 0),
    ],
}


class DataFlowAnalyzer(Analyzer):
    """Best-effort data-flow analysis for AI-generated code.

    Uses regex heuristics to track whether dangerous function arguments
    originate from user-controlled sources.

    This is NOT a full AST data-flow framework.  It provides a confidence
    signal that downstream rules can use to reduce false positives.
    """

    layer: int = 3
    name: str = "data_flow_analyzer"

    _MAX_CACHE_SIZE = 1024

    def __init__(self) -> None:
        super().__init__()
        self._cache: OrderedDict[int, dict[str, Any]] = OrderedDict()

    def analyze(self, content: str, context: AnalysisContext) -> AnalysisContext:
        """Run data-flow analysis and populate *context*."""
        if not content.strip() or len(content) < 20:
            return context  # Too short for meaningful analysis
        if len(content) > 10000:
            return context  # Too large for heuristic data-flow analysis

        cache_key = hash(content)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._cache.move_to_end(cache_key)
            context.structural_matches.update(cached)
            return context

        language = context.detected_language or "python"
        results = self._analyze(content, language)

        if results:
            context.structural_matches.setdefault("data_flow", results)
            self._cache[cache_key] = {"data_flow": results}
            while len(self._cache) > self._MAX_CACHE_SIZE:
                self._cache.popitem(last=False)

        return context

    def clear_cache(self) -> None:
        self._cache.clear()

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def _analyze(self, content: str, language: str) -> list[dict[str, Any]]:
        """Run full analysis and return findings list."""
        findings: list[dict[str, Any]] = []

        # 1. Find user-controlled variables
        tainted_vars = self._find_tainted_vars(content, language)

        # 2. Find dangerous sinks
        sinks = self._find_sinks(content, language)

        # 3. For each sink, determine if any argument is tainted
        for sink_name, arg_idx, start_pos in sinks:
            tainted = self._is_tainted(content, start_pos, arg_idx, tainted_vars, language)
            sanitised = self._is_sanitised(content, start_pos, arg_idx, language)

            if tainted:
                confidence = 1.0 if tainted == "direct" else 0.6
                findings.append({
                    "sink": sink_name,
                    "position": start_pos,
                    "data_flow": "user_controlled",
                    "confidence": confidence,
                    "detail": f"Dangerous function {sink_name} receives user-controlled input",
                })
            elif sanitised:
                findings.append({
                    "sink": sink_name,
                    "position": start_pos,
                    "data_flow": "sanitised",
                    "confidence": 0.1,
                    "detail": f"Dangerous function {sink_name} has sanitised input",
                })

        return findings

    # ------------------------------------------------------------------
    # Taint tracking
    # ------------------------------------------------------------------

    def _find_tainted_vars(self, content: str, language: str) -> set[str]:
        """Find variables that are assigned from user-controlled sources.

        Returns: set of variable names (possibly empty).
        """
        tainted: set[str] = set()
        sources = _USER_SOURCES.get(language, _USER_SOURCES["python"])

        for source in sources:
            esc_source = re.escape(source)
            # Direct usage: dangerous(source)
            if source in content:
                # The source itself is tainted — we can mark it
                tainted.add("__direct__")

            # Assignment: var = source
            assign_pattern = re.compile(
                r'(?:var|let|const|val|let\s+mut)?\s*(\w+)\s*[=:].*?' + esc_source,
                re.IGNORECASE,
            )
            for m in assign_pattern.finditer(content):
                tainted.add(m.group(1))

        return tainted

    def _find_sinks(
        self,
        content: str,
        language: str,
    ) -> list[tuple[str, int, int]]:
        """Find dangerous function call positions.

        Returns: list of (sink_name, arg_index, start_position).
        """
        found: list[tuple[str, int, int]] = []
        sinks = _SINKS.get(language, _SINKS.get("python", []))

        for sink_name, arg_idx in sinks:
            pattern = re.compile(re.escape(sink_name) + r'\s*\(')
            for m in pattern.finditer(content):
                found.append((sink_name, arg_idx, m.start()))

        return found

    def _is_tainted(
        self,
        content: str,
        sink_pos: int,
        arg_idx: int,
        tainted_vars: set[str],
        language: str,
    ) -> str | None:
        """Determine if the *arg_idx*-th argument of the sink at *sink_pos* is tainted.

        Returns:
          - ``"direct"`` — argument is a user source literal
          - ``"indirect"`` — argument traces to a tainted variable
          - ``None`` — not tainted (hardcoded constant)
        """
        # Extract the argument expression
        arg_text = self._extract_arg(content, sink_pos, arg_idx)
        if not arg_text:
            return None

        arg_text = arg_text.strip()

        # Direct: is the argument itself a user source?
        sources = _USER_SOURCES.get(language, _USER_SOURCES["python"])
        for src in sources:
            if arg_text.startswith(src.rstrip("(")):
                return "direct"

        # Direct: is it a plain string literal? (hardcoded = safe)
        is_string_literal = (
            arg_text.startswith('"') or arg_text.startswith("'") or arg_text.startswith("`")
            or arg_text.startswith('f"') or arg_text.startswith("f'") or arg_text.startswith('b"')
            or arg_text.startswith("r'") or arg_text.startswith('r"')
        )
        if is_string_literal:
            # Check for interpolation or concatenation (f-strings, format, +, $)
            if "{" in arg_text or "${" in arg_text or "+" in arg_text:
                return "indirect"
            if "," in arg_text:
                return "indirect"
            return None  # Hardcoded string = safe

        # Indirect: is it a tainted variable?
        if arg_text in tainted_vars:
            return "indirect"

        # Generic variable without clear origin — possible but uncertain
        if re.match(r'^[A-Za-z_]\w*$', arg_text):
            return "indirect"

        return None

    def _is_sanitised(
        self,
        content: str,
        sink_pos: int,
        arg_idx: int,
        language: str,
    ) -> bool:
        """Check if the argument at *sink_pos* passes through a sanitiser."""
        arg_text = self._extract_arg(content, sink_pos, arg_idx)
        if not arg_text:
            return False

        sanitizers = _SANITISERS.get(language, _SANITISERS.get("python", []))
        for s in sanitizers:
            if s in arg_text:
                return True
        return False

    # ------------------------------------------------------------------
    # Argument extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_arg(content: str, call_start: int, arg_idx: int) -> str | None:
        """Extract the *arg_idx*-th argument from a function call at *call_start*.

        Uses simple parenthesis counting — handles one level of nesting.
        """
        paren_start = content.find("(", call_start)
        if paren_start == -1:
            return None

        # Parse arguments (handles nested parens at depth 1)
        depth = 0
        current_arg: list[str] = []
        arg_num = 0
        in_arg = False

        for i in range(paren_start + 1, len(content)):
            ch = content[i]

            if ch == "(":
                depth += 1
                if in_arg:
                    current_arg.append(ch)
            elif ch == ")":
                if depth == 0:
                    # End of call
                    if arg_num == arg_idx and current_arg:
                        return "".join(current_arg).strip()
                    return None
                depth -= 1
                if in_arg:
                    current_arg.append(ch)
            elif ch == "," and depth == 0:
                if arg_num == arg_idx:
                    return "".join(current_arg).strip()
                arg_num += 1
                current_arg = []
                in_arg = False
            else:
                current_arg.append(ch)
                in_arg = True

        return None
