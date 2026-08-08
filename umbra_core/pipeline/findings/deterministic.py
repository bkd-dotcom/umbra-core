"""Deterministic SAST floor — the always-on, offline, dependency-free detector.

This is the TRUSTWORTHY layer: pure static analysis, no model, no network. It
covers the OWASP-class vulnerabilities that LLM scanners (codex-security /
claude-code-security-review) detect, so umbra-core reaches detection parity
without depending on a paid model or a network round-trip.

Two complementary strategies:
- **Python files** are parsed with the standard-library ``ast`` module, so rules
  match on real call/attribute structure (e.g. ``pickle.loads(...)`` on a request
  value) rather than fragile substrings — this is what keeps false positives low.
- **JavaScript / TypeScript / generic** files use targeted regex rules (no JS
  parser in the stdlib); patterns are written narrowly to require a user-input or
  concatenation signal before flagging.

Every rule cites a CWE and returns a conservative fixed confidence. A rule fires
on the SOURCE as written; the admission pipeline decides what authority a fix for
it can earn — this module only reports.
"""
from __future__ import annotations

import ast
import re

from .model import Finding, Severity, Source

# ---------------------------------------------------------------------------
# Signals shared across rules
# ---------------------------------------------------------------------------

# Names that indicate a value is (or may be) attacker-controlled. Used to keep
# injection rules high-confidence: a sink is only flagged HIGH when a tainted-ish
# source is nearby.
_USER_INPUT_HINTS = re.compile(
    r"(?i)\b(request|req)\b|\bargs\b|\bform\b|\bquery\b|\bparams?\b|\bgetenv\b|"
    r"\binput\(|\bstdin\b|\bpayload\b|\buser[_-]?input\b|\bbody\b|\bcookies?\b"
)

# Placeholder markers so example/doc secrets don't trip the secret rule.
_PLACEHOLDER_HINTS = ("example", "placeholder", "replace", "your-", "xxxx", "dummy",
                      "sample", "changeme", "redacted", "<", "test-", "fake")


def _looks_placeholder(text: str) -> bool:
    low = text.lower()
    return any(h in low for h in _PLACEHOLDER_HINTS)


def _is_fixture_path(file: str) -> bool:
    parts = [p.lower() for p in file.replace("\\", "/").split("/")]
    return any(seg in {"tests", "test", "fixtures", "fixture", "__mocks__",
                       "mocks", "examples", "example", "testdata"} for seg in parts[:-1])


# ---------------------------------------------------------------------------
# Python AST rules
# ---------------------------------------------------------------------------


def _attr_chain(node: ast.AST) -> str:
    """Render a dotted call target, e.g. ``subprocess.check_output`` or ``pickle.loads``."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _contains_user_input(node: ast.AST) -> bool:
    """Best-effort taint hint: does this subtree reference a request/args/form/etc?"""
    try:
        src = ast.unparse(node)
    except Exception:  # noqa: BLE001 - unparse can fail on odd nodes
        return False
    return bool(_USER_INPUT_HINTS.search(src))


def _has_concat_or_format(node: ast.AST) -> bool:
    """True if ``node`` is a string built by +, %, .format(), or an f-string —
    the shape that turns user input into an injection."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.JoinedStr):  # f-string
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def _name_of(node: ast.AST) -> str | None:
    return node.id if isinstance(node, ast.Name) else None


class _PyVisitor(ast.NodeVisitor):
    """AST visitor with lightweight intraprocedural taint tracking.

    Within each function we track the set of local variable names that were
    assigned (directly or transitively) from a user-input source (request/args/
    form/…). A sink (execute/open/subprocess/…) that uses a tainted variable — or
    an inline user-input reference — is flagged. This catches the common pattern
    where input flows through one intermediate variable, without the false
    positives of flagging every string operation.
    """

    def __init__(self, file: str) -> None:
        self.file = file
        self.findings: list[Finding] = []
        self._tainted: set[str] = set()

    def _add(self, node: ast.AST, rule_id: str, category: str, severity: Severity,
             title: str, detail: str, remediation: str, confidence: float, cwe: str) -> None:
        self.findings.append(Finding(
            rule_id=rule_id, category=category, severity=severity, file=self.file,
            line=getattr(node, "lineno", 0), title=title, detail=detail,
            remediation=remediation, confidence=confidence, source=Source.DETERMINISTIC, cwe=cwe,
        ))

    def _is_tainted(self, node: ast.AST) -> bool:
        """True if ``node`` references user input directly OR via a tainted local."""
        if _contains_user_input(node):
            return True
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in self._tainted:
                return True
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        saved = self._tainted
        self._tainted = set()  # fresh taint scope per function
        self.generic_visit(node)
        self._tainted = saved

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Return(self, node: ast.Return) -> None:
        # Reflected XSS: returning an HTML string built from a tainted value from a
        # request handler (common Flask pattern: return "<h1>" + name).
        if node.value is not None and _has_concat_or_format(node.value) and self._is_tainted(node.value):
            try:
                src = ast.unparse(node.value)
            except Exception:  # noqa: BLE001
                src = ""
            if re.search(r"<[a-zA-Z!/]", src):  # contains an HTML-ish tag
                self._add(node, "py.xss_reflected", "xss", Severity.MEDIUM,
                          "Reflected XSS: unescaped user input in HTML response",
                          "A request handler returns an HTML string built from user input without "
                          "escaping.",
                          "HTML-escape the value (markupsafe.escape) or use an autoescaping template.",
                          0.8, "CWE-79")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        # Taint propagation: if the RHS references user input or an already-tainted
        # variable, mark the assigned target name(s) as tainted for this scope.
        if self._is_tainted(node.value):
            for t in node.targets:
                name = _name_of(t)
                if name:
                    self._tainted.add(name)

        # Hardcoded secret: NAME = "literal" where NAME looks secret-ish and the
        # value is a non-placeholder string of meaningful length.
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val = node.value.value
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            secretish = re.compile(r"(?i)(secret|password|passwd|api[_-]?key|token|jwt|credential)")
            if (any(secretish.search(n) for n in names) and len(val) >= 8
                    and not _looks_placeholder(val) and not _is_fixture_path(self.file)):
                self._add(node, "py.hardcoded_secret", "hardcoded_secret", Severity.HIGH,
                          "Hardcoded secret assigned in source",
                          f"A secret-looking variable ({', '.join(names)}) is assigned a literal "
                          "string. Committing a credential in source is a leak.",
                          "Load from an environment variable or secrets manager; rotate the value.",
                          0.85, "CWE-798")
            # Also catch sk-/ghp_ style tokens regardless of variable name.
            if re.search(r"\bsk-[A-Za-z0-9_-]{16,}\b|\bghp_[A-Za-z0-9]{20,}\b", val) and not _looks_placeholder(val):
                self._add(node, "py.hardcoded_secret_pattern", "hardcoded_secret", Severity.HIGH,
                          "Hardcoded credential (recognised token shape)",
                          "An assigned literal matches a known credential shape (OpenAI/GitHub).",
                          "Remove the credential from source and rotate it.",
                          0.9, "CWE-798")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: C901 - dispatch table by design
        target = _attr_chain(node.func)
        args = node.args

        # --- SQL injection: cursor.execute(<tainted string>) ---
        # Parameterised queries never pass a user-tainted string as the query text;
        # a tainted first arg to execute() (inline concat OR a variable built from
        # input) is the injection shape.
        if target.endswith("execute") and args:
            q = args[0]
            inline = _has_concat_or_format(q) and self._is_tainted(q)
            via_var = isinstance(q, ast.Name) and q.id in self._tainted
            if inline or via_var:
                self._add(node, "py.sql_injection", "sql_injection", Severity.HIGH,
                          "SQL query built from user input",
                          "A SQL string is assembled from a user-controlled value and passed to "
                          "execute() instead of being parameterised.",
                          "Use parameterised queries: cursor.execute(sql, (params,)).",
                          0.9, "CWE-89")

        # --- Command injection: subprocess/os.system with shell / concat ---
        if target in ("os.system", "os.popen") and args:
            if self._is_tainted(args[0]) or _has_concat_or_format(args[0]):
                self._add(node, "py.command_injection_os_system", "command_injection", Severity.HIGH,
                          "OS command built from user input",
                          f"{target}() runs a shell command assembled from user input.",
                          "Avoid the shell; use subprocess with an argument list and validated inputs.",
                          0.9, "CWE-78")
        if target.startswith("subprocess.") or target.endswith(("check_output", "check_call", "call", "run", "Popen")):
            shell_true = any(
                isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords if kw.arg == "shell"
            )
            if shell_true and args and (_has_concat_or_format(args[0]) or self._is_tainted(args[0])):
                self._add(node, "py.command_injection_shell", "command_injection", Severity.HIGH,
                          "subprocess with shell=True on user input",
                          "A subprocess call uses shell=True with a command string built from user input.",
                          "Drop shell=True and pass args as a list; validate/allowlist inputs.",
                          0.92, "CWE-78")

        # --- Unsafe deserialisation ---
        if target in ("pickle.loads", "pickle.load", "cPickle.loads", "_pickle.loads"):
            self._add(node, "py.insecure_deserialization", "insecure_deserialization", Severity.HIGH,
                      "Unpickling untrusted data",
                      "pickle.loads/load can execute arbitrary code during deserialisation.",
                      "Never unpickle untrusted input; use JSON or a signed, verified format.",
                      0.88 if self._is_tainted(node) else 0.8, "CWE-502")
        if target in ("yaml.load",) and not any(kw.arg == "Loader" for kw in node.keywords):
            self._add(node, "py.yaml_load", "insecure_deserialization", Severity.HIGH,
                      "yaml.load without SafeLoader",
                      "yaml.load without a safe Loader can instantiate arbitrary Python objects.",
                      "Use yaml.safe_load or pass Loader=yaml.SafeLoader.",
                      0.82, "CWE-502")

        # --- eval / exec code injection ---
        if target in ("eval", "exec"):
            self._add(node, "py.code_injection_eval", "code_injection", Severity.HIGH,
                      f"Dynamic code execution via {target}()",
                      f"{target}() executes arbitrary code; on any user-influenced input this is RCE.",
                      "Remove eval/exec; use ast.literal_eval or explicit dispatch.",
                      0.85, "CWE-95")

        # --- Weak hashing (md5/sha1), esp. for passwords ---
        if target in ("hashlib.md5", "hashlib.sha1"):
            algo = target.split(".")[-1]
            self._add(node, "py.weak_hash", "weak_crypto", Severity.MEDIUM,
                      f"Weak hash algorithm {algo}",
                      f"{algo} is fast and broken for security use (esp. password hashing).",
                      "Use bcrypt/scrypt/Argon2 for passwords; SHA-256+ for integrity.",
                      0.8, "CWE-327")

        # --- Path traversal: open(<tainted path>) ---
        if target in ("open",) and args:
            a0 = args[0]
            # Fire when the path is built from (or is) a tainted value: an inline
            # concat/format containing user input, a concat containing a tainted
            # local, or a bare tainted variable.
            if self._is_tainted(a0):
                self._add(node, "py.path_traversal", "path_traversal", Severity.HIGH,
                          "File path built from user input",
                          "A filesystem path is built from user input without normalisation, "
                          "allowing ../ traversal.",
                          "Canonicalise with os.path.realpath and verify it stays under a base dir; "
                          "or map through an allowlist.",
                          0.85, "CWE-22")

        # --- SSRF: outbound request to a tainted URL ---
        if target in ("requests.get", "requests.post", "requests.request", "requests.put",
                      "requests.delete", "requests.head", "urllib.request.urlopen",
                      "httpx.get", "httpx.post", "aiohttp.request") and args:
            if self._is_tainted(args[0]):
                self._add(node, "py.ssrf", "ssrf", Severity.HIGH,
                          "Server-side request to a user-controlled URL (SSRF)",
                          "An outbound HTTP request targets a user-controlled URL, allowing SSRF "
                          "to internal services or cloud metadata.",
                          "Allowlist permitted hosts/schemes; reject internal/link-local targets.",
                          0.82, "CWE-918")

        # --- SSTI: render_template_string on tainted input ---
        if target.endswith("render_template_string") and args:
            if self._is_tainted(args[0]):
                self._add(node, "py.ssti", "template_injection", Severity.HIGH,
                          "Server-side template injection",
                          "User input flows into render_template_string; Jinja2 will evaluate "
                          "template expressions (RCE surface).",
                          "Render a fixed template and pass user data as context variables.",
                          0.82, "CWE-1336")

        # --- JWT signature verification disabled / alg none ---
        if target.endswith("decode"):
            for kw in node.keywords:
                if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                    for k, v in zip(kw.value.keys, kw.value.values):
                        if (isinstance(k, ast.Constant) and k.value == "verify_signature"
                                and isinstance(v, ast.Constant) and v.value is False):
                            self._add(node, "py.jwt_no_verify", "auth_bypass", Severity.HIGH,
                                      "JWT decoded without signature verification",
                                      "verify_signature=False accepts any token, enabling forgery.",
                                      "Verify the signature with the expected algorithm and key.",
                                      0.85, "CWE-347")
                if kw.arg in ("algorithms", "algorithm"):
                    vals = []
                    if isinstance(kw.value, ast.Constant):
                        vals = [kw.value.value]
                    elif isinstance(kw.value, (ast.List, ast.Tuple)):
                        vals = [e.value for e in kw.value.elts if isinstance(e, ast.Constant)]
                    if any(str(x).lower() == "none" for x in vals):
                        self._add(node, "py.jwt_alg_none", "auth_bypass", Severity.HIGH,
                                  "JWT accepts the 'none' algorithm",
                                  "Allowing alg=none means unsigned tokens are accepted.",
                                  "Pin a strong algorithm (e.g. RS256/HS256); never allow 'none'.",
                                  0.85, "CWE-347")

        # --- Django ORM raw/extra SQL from tainted input ---
        if target.endswith((".extra", ".raw", ".RawSQL")) or target in ("RawSQL",):
            tainted_arg = any(self._is_tainted(a) for a in args) or any(
                self._is_tainted(kw.value) for kw in node.keywords
            )
            list_with_format = any(
                _has_concat_or_format(el) and self._is_tainted(el)
                for kw in node.keywords if isinstance(kw.value, ast.List)
                for el in kw.value.elts
            )
            if tainted_arg or list_with_format:
                self._add(node, "py.django_raw_sql", "sql_injection", Severity.HIGH,
                          "Django raw/extra SQL built from user input",
                          "QuerySet.extra()/raw()/RawSQL with a string built from user input is "
                          "SQL injection.",
                          "Use parameterised params= / the ORM filter API instead of string building.",
                          0.85, "CWE-89")

        # --- Flask debug=True (app.run(debug=True)) ---
        if target.endswith("run"):
            if any(kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                   for kw in node.keywords):
                self._add(node, "py.flask_debug", "debug_enabled", Severity.HIGH,
                          "Debug mode enabled",
                          "Running with debug=True exposes the interactive debugger (RCE surface) "
                          "and verbose errors.",
                          "Never enable debug in production; gate on an env flag defaulting off.",
                          0.8, "CWE-489")

        # --- TLS verification disabled ---
        if any(kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
               for kw in node.keywords):
            self._add(node, "py.tls_verify_disabled", "tls_disabled", Severity.HIGH,
                      "TLS certificate verification disabled",
                      "verify=False disables certificate validation, enabling MITM.",
                      "Keep verification on; fix the trust chain instead.",
                      0.85, "CWE-295")

        self.generic_visit(node)


def _scan_python(file: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    v = _PyVisitor(file)
    v.visit(tree)
    return v.findings


# ---------------------------------------------------------------------------
# Regex rules (JS/TS + language-agnostic)
# ---------------------------------------------------------------------------

# Each rule: (rule_id, category, severity, cwe, compiled pattern, title, detail, remediation, confidence)
_JS_RULES: list[tuple] = [
    ("js.hardcoded_secret", "hardcoded_secret", Severity.HIGH, "CWE-798",
     re.compile(r"(?i)(const|let|var)\s+\w*(secret|password|token|api[_-]?key|jwt)\w*\s*=\s*['\"][^'\"]{8,}['\"]"),
     "Hardcoded secret in source",
     "A secret-looking constant is assigned a literal string.",
     "Load from process.env or a secrets manager; rotate the value.", 0.82),
    ("js.command_injection", "command_injection", Severity.HIGH, "CWE-78",
     re.compile(r"(?i)\b(exec|execSync)\s*\(\s*[`'\"][^`'\"]*[`'\"]?\s*\+|(exec|execSync)\s*\(\s*`[^`]*\$\{"),
     "Command injection via child_process.exec",
     "A shell command is assembled by concatenation/interpolation and run via exec().",
     "Use execFile/spawn with an argument array; validate inputs.", 0.85),
    ("js.insecure_random", "insecure_randomness", Severity.MEDIUM, "CWE-330",
     re.compile(r"(?i)Math\.random\s*\(\s*\)"),
     "Insecure randomness for security value",
     "Math.random() is not cryptographically secure and is predictable.",
     "Use crypto.randomBytes() or crypto.randomUUID() for tokens.", 0.7),
    ("js.eval", "code_injection", Severity.HIGH, "CWE-95",
     re.compile(r"(?<![.\w])eval\s*\("),
     "Dynamic code execution via eval()",
     "eval() executes arbitrary code; on user input this is RCE.",
     "Remove eval; use explicit parsing/dispatch.", 0.8),
    ("js.ssrf", "ssrf", Severity.HIGH, "CWE-918",
     re.compile(r"(?i)\b(fetch|axios(?:\.get|\.post|\.request)?|http\.get|https\.get|request|got|superagent)\s*\(\s*(?:req\.(query|params|body|headers)|`[^`]*\$\{req\.(query|params|body|headers)|['\"][^'\"]*['\"]\s*\+\s*req\.(query|params|body|headers))"),
     "Server-Side Request Forgery (SSRF) via HTTP request",
     "An HTTP request fetches a URL built directly from user input.",
     "Allowlist target URLs/domains; do not fetch arbitrary user-supplied URLs.", 0.82),
]

# XSS: unescaped user input written into an HTML/response string. Language-agnostic
# but narrow — requires an HTML tag literal AND a request/query/param reference on
# the same line.
_XSS_RULE = re.compile(
    r"(?is)(res\.send|return|innerHTML|write)\s*\(?.*<[a-z].*?>.*"
    r"(req\.query|req\.params|req\.body|request\.args|request\.form|flask\.request|params\.|query\.)"
)
# If the user value is passed through an escaping/sanitising helper on the same
# line, it is NOT reflected XSS — suppress the finding (false-positive guard).
_XSS_ESCAPE_GUARD = re.compile(
    r"(?i)(escape|escapehtml|sanitize|sanitise|encodeuri|dompurify|markupsafe|"
    r"htmlspecialchars|xss_clean|htmlescape)\s*\("
)

# NoSQL injection: a Mongo-style query call whose object literal takes a req.* value
# directly (find/findOne/updateOne/deleteOne/etc). Matches across newlines.
_NOSQL_RULE = re.compile(
    r"(?is)\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|count|aggregate)\s*\(\s*\{"
    r"[^}]*\breq\.(body|query|params)\b"
)


def _scan_regex(file: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    low = file.lower()
    is_js = low.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        if is_js:
            for (rid, cat, sev, cwe, pat, title, detail, rem, conf) in _JS_RULES:
                if not pat.search(line):
                    continue
                # Only the secret rule skips on placeholder-looking values.
                if cat == "hardcoded_secret" and _looks_placeholder(line):
                    continue
                findings.append(Finding(
                    rule_id=rid, category=cat, severity=sev, file=file, line=idx,
                    title=title, detail=detail, remediation=rem, confidence=conf,
                    source=Source.DETERMINISTIC, cwe=cwe,
                ))
        # XSS check on the line (both JS and templated Python responses), unless the
        # user value is escaped/sanitised on the same line.
        if _XSS_RULE.search(line) and not _XSS_ESCAPE_GUARD.search(line):
            findings.append(Finding(
                rule_id="xss.reflected", category="xss", severity=Severity.MEDIUM, file=file, line=idx,
                title="Reflected XSS: unescaped user input in response",
                detail="User-controlled input is written into an HTML response without escaping.",
                remediation="HTML-escape output or use an autoescaping template engine.",
                confidence=0.78, source=Source.DETERMINISTIC, cwe="CWE-79",
            ))
    # NoSQL injection (multi-line): a Mongo query object built directly from req.*
    # values without sanitisation, e.g. findOne({ username: req.body.username }).
    if is_js:
        m = _NOSQL_RULE.search(text)
        if m:
            line_no = text[: m.start()].count("\n") + 1
            findings.append(Finding(
                rule_id="js.nosql_injection", category="nosql_injection", severity=Severity.HIGH,
                file=file, line=line_no,
                title="NoSQL injection: user input in a query object",
                detail="A database query object is built directly from req.* values; an attacker "
                       "can pass operators (e.g. {$ne: null}) to bypass authentication or matching.",
                remediation="Coerce inputs to strings and validate types; never spread raw req input "
                            "into a query.",
                confidence=0.72, source=Source.DETERMINISTIC, cwe="CWE-943",
            ))
    return findings


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def scan_source(file: str, text: str) -> list[Finding]:
    """Run every deterministic rule over one file's source text."""
    from .lang_taint import scan_lang_taint
    from .multilang import scan_multilang

    findings: list[Finding] = []
    if file.lower().endswith(".py"):
        findings += _scan_python(file, text)
    findings += _scan_regex(file, text)
    findings += scan_multilang(file, text)
    findings += scan_lang_taint(file, text)
    # Deduplicate identical (file, line, category) hits from overlapping rules.
    seen: set[tuple[str, int, str]] = set()
    unique: list[Finding] = []
    for f in findings:
        if f.key() not in seen:
            seen.add(f.key())
            unique.append(f)
    return unique
