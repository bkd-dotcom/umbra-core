"""Generic line-based taint tracking for languages without a stdlib parser.

Python gets precise AST taint (see ``deterministic.py`` + ``crossfile.py``). Go,
Java, PHP, Ruby and C# have no parser in the Python stdlib, so writing full ASTs
would be fragile and huge. Instead this module does a pragmatic, dependency-free
**intra-file taint pass** driven by declarative per-language specs:

1. **Sources** — expressions that introduce user input (``r.URL.Query()``,
   ``request.getParameter``, ``$_GET``, ``params[...]``, ``Request.Query`` …).
2. **Assignments** — ``lhs = rhs`` (per language) so taint propagates through
   intermediate variables (the gap the pure per-line regex rules had).
3. **Sinks** — dangerous calls (``db.Query``, ``executeQuery``, ``mysqli_query``,
   ``system`` …). A sink fires when its line references a tainted variable OR an
   inline source, and (for concat-style sinks) shows a concatenation/interpolation.
4. **Sanitizers** — if a tainted value passes through a recognised sanitizer, its
   taint is cleared (keeps false positives at zero on prepared statements etc.).

This is deliberately conservative: name-based, single-file, one assignment level of
propagation carried forward line-by-line. It catches the common "source → local →
sink" flow the LLM scanners rely on reading, while staying deterministic and free.
It complements (does not replace) the direct-pattern rules in ``multilang.py``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Finding, Severity, Source


@dataclass(frozen=True)
class SinkSpec:
    rule_id: str
    category: str
    cwe: str
    title: str
    detail: str
    remediation: str
    pattern: re.Pattern[str]
    requires_concat: bool = True  # False for sinks where the value itself is the payload
    confidence: float = 0.8
    severity: Severity = Severity.HIGH


@dataclass(frozen=True)
class LangTaintSpec:
    exts: tuple[str, ...]
    # A source expression producing user input (matched anywhere on a line).
    source: re.Pattern[str]
    # Assignment: group(1)=lhs identifier, group(2)=rhs (best-effort per language).
    assign: re.Pattern[str]
    # Concatenation/interpolation signal (indicates a string is being built).
    concat: re.Pattern[str]
    # Sanitizers that clear taint if applied to the value.
    sanitizer: re.Pattern[str]
    sinks: tuple[SinkSpec, ...] = field(default_factory=tuple)
    # Identifier shape for the language (to detect tainted-var references).
    ident: re.Pattern[str] = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


# --- identifier / helpers ---------------------------------------------------

_CONCAT_GENERIC = re.compile(r"\+|\bfmt\.Sprintf\b|#\{|\$\{|\.\s*format\s*\(|\"\s*\.\s*\$|%s")


def _idents(text: str, pat: re.Pattern[str]) -> set[str]:
    return set(pat.findall(text))


# --- per-language specs -----------------------------------------------------

_GO = LangTaintSpec(
    exts=(".go",),
    source=re.compile(r"r\.URL\.Query\(\)|r\.FormValue\(|r\.PostFormValue\(|mux\.Vars\(|c\.Query\(|c\.Param\("),
    assign=re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:?=\s*(.+)$"),
    concat=re.compile(r"\+|fmt\.Sprintf"),
    sanitizer=re.compile(r"strconv\.(Atoi|ParseInt)|regexp\.MustCompile|template\.HTMLEscapeString"),
    sinks=(
        SinkSpec("go.taint.sql_injection", "sql_injection", "CWE-89",
                 "SQL built from user input (taint)",
                 "A SQL statement is built from a user-controlled value and executed.",
                 "Use parameterised queries (db.Query with $1 placeholders).",
                 re.compile(r"\b(db|tx|conn|stmt|DB)\w*\.(Query|QueryRow|Exec)(Context)?\s*\("), confidence=0.8),
        SinkSpec("go.taint.command_injection", "command_injection", "CWE-78",
                 "OS command built from user input (taint)",
                 "A command is built from user input and run via exec.Command/os.",
                 "Pass args separately; never build a shell string.",
                 re.compile(r"exec\.Command\s*\("), confidence=0.8),
    ),
)

_JAVA = LangTaintSpec(
    exts=(".java",),
    source=re.compile(r"\.getParameter\s*\(|\.getHeader\s*\(|\.getQueryString\s*\(|@RequestParam|@PathVariable|\.getInputStream\s*\("),
    assign=re.compile(r"^\s*(?:final\s+)?[A-Za-z_$][\w<>\[\].]*\s+([A-Za-z_$]\w*)\s*=\s*(.+);?\s*$"),
    concat=re.compile(r"\+"),
    sanitizer=re.compile(r"Integer\.parseInt|Long\.parseLong|Pattern\.matches|StringEscapeUtils|PreparedStatement"),
    sinks=(
        SinkSpec("java.taint.sql_injection", "sql_injection", "CWE-89",
                 "SQL built from user input (taint)",
                 "A JDBC/JPA query is concatenated from user input and executed.",
                 "Use PreparedStatement with bound parameters.",
                 re.compile(r"\.(executeQuery|executeUpdate|execute|createQuery)\s*\("), confidence=0.8),
        SinkSpec("java.taint.command_injection", "command_injection", "CWE-78",
                 "OS command built from user input (taint)",
                 "A command is built from user input and executed.",
                 "Use ProcessBuilder with an argument list; validate inputs.",
                 re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\("), confidence=0.8),
    ),
)

_PHP = LangTaintSpec(
    exts=(".php",),
    source=re.compile(r"\$_(GET|POST|REQUEST|COOKIE)\b"),
    assign=re.compile(r"(\$[A-Za-z_]\w*)\s*=\s*(.+);?\s*$"),
    concat=re.compile(r"\.|\"\s*\$|\$\w+"),
    sanitizer=re.compile(r"intval\s*\(|\(int\)|mysqli_real_escape_string|htmlspecialchars|preg_match|filter_var|PDO::PARAM"),
    sinks=(
        SinkSpec("php.taint.sql_injection", "sql_injection", "CWE-89",
                 "SQL built from user input (taint)",
                 "A query is built from $_GET/$_POST (possibly via a variable) and executed.",
                 "Use prepared statements (PDO/mysqli bound params).",
                 re.compile(r"(mysqli_query|mysql_query|->query|->exec)\s*\("), confidence=0.82),
        SinkSpec("php.taint.command_injection", "command_injection", "CWE-78",
                 "OS command built from user input (taint)",
                 "A shell command includes user input (possibly via a variable).",
                 "Avoid shell calls on user input; use escapeshellarg + allowlist.",
                 re.compile(r"(system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
                 requires_concat=False, confidence=0.8),
    ),
)

_RUBY = LangTaintSpec(
    exts=(".rb",),
    source=re.compile(r"params\s*\[|request\.(params|query_parameters|GET|POST)"),
    assign=re.compile(r"^\s*([a-z_]\w*)\s*=\s*(.+)$"),
    concat=re.compile(r"#\{|\+"),
    sanitizer=re.compile(r"\.to_i\b|Integer\s*\(|sanitize|ActiveRecord::Base\.sanitize"),
    sinks=(
        SinkSpec("ruby.taint.sql_injection", "sql_injection", "CWE-89",
                 "SQL built from user input (taint)",
                 "An ActiveRecord query interpolates user input.",
                 "Use parameterised queries: where('x = ?', val).",
                 re.compile(r"\.(where|find_by_sql|execute)\s*\(|\.where\s+"), confidence=0.78),
        SinkSpec("ruby.taint.command_injection", "command_injection", "CWE-78",
                 "OS command built from user input (taint)",
                 "A shell command interpolates user input.",
                 "Use system with separate args; validate inputs.",
                 re.compile(r"\b(system|exec)\s*\(|`[^`]"), requires_concat=False, confidence=0.75),
    ),
)

_CSHARP = LangTaintSpec(
    exts=(".cs",),
    source=re.compile(r"(?i)request\.(Query|Form|QueryString|Params)|\brequest\[|\[FromQuery\]|\[FromBody\]|\[FromRoute\]"),
    assign=re.compile(r"^\s*(?:var|string|int|object)?\s*([A-Za-z_]\w*)\s*=\s*(.+);?\s*$"),
    concat=re.compile(r"\+|\$\""),
    sanitizer=re.compile(r"int\.Parse|Int32\.TryParse|Regex\.IsMatch|HttpUtility\.HtmlEncode|SqlParameter"),
    sinks=(
        SinkSpec("csharp.taint.sql_injection", "sql_injection", "CWE-89",
                 "SQL built from user input (taint)",
                 "A SqlCommand text is built from request input.",
                 "Use parameterised SqlCommand with SqlParameter.",
                 re.compile(r"new\s+SqlCommand\s*\(|CommandText\s*="), confidence=0.78),
        SinkSpec("csharp.taint.command_injection", "command_injection", "CWE-78",
                 "OS command built from user input (taint)",
                 "A process is started with input-derived arguments.",
                 "Use ArgumentList; validate inputs.",
                 re.compile(r"Process\.Start\s*\("), confidence=0.75),
    ),
)

_JS = LangTaintSpec(
    exts=(".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    source=re.compile(r"\breq\.(query|params|body|headers|cookies)\b"),
    assign=re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+);?\s*$"),
    concat=re.compile(r"\+|\$`|\$\{"),
    sanitizer=re.compile(r"encodeURIComponent|sanitizeUrl|allowlist"),
    sinks=(
        SinkSpec("js.taint.ssrf", "ssrf", "CWE-918",
                 "Server-Side Request Forgery (SSRF) via user input (taint)",
                 "An HTTP request is sent to a URL derived from user input.",
                 "Allowlist permitted destination URLs; validate protocol and host.",
                 re.compile(r"\b(fetch|axios(?:\.get|\.post|\.request)?|http\.get|https\.get|request|got|superagent)\s*\("),
                 requires_concat=False, confidence=0.8),
    ),
)

_SPECS: list[LangTaintSpec] = [_GO, _JAVA, _PHP, _RUBY, _CSHARP, _JS]
_EXT_TO_SPEC: dict[str, LangTaintSpec] = {e: s for s in _SPECS for e in s.exts}

LANG_TAINT_EXTS = frozenset(_EXT_TO_SPEC)


# Parameterised-query signals: if a SQL sink line uses placeholders and passes the
# value as a separate argument, it is NOT injection (bound parameter). Covers
# Go/pg ($1), JDBC/PDO/ODBC (?), and named params (:name, @name).
_PARAM_PLACEHOLDER = re.compile(r"(?<![\w$:])(\$\d+|\?|:[A-Za-z_]\w*|@[A-Za-z_]\w*)(?![\w:])")


def _rhs_is_tainted(rhs: str, spec: LangTaintSpec, tainted: set[str]) -> bool:
    if spec.sanitizer.search(rhs):
        return False
    if spec.source.search(rhs):
        return True
    return any(v in tainted for v in _idents(rhs, spec.ident))


def scan_lang_taint(file: str, text: str) -> list[Finding]:
    """Intra-file taint pass for a supported non-Python language. Returns findings
    where a sink line uses a tainted variable or an inline source."""
    import os

    spec = _EXT_TO_SPEC.get(os.path.splitext(file.lower())[1])
    if spec is None:
        return []

    tainted: set[str] = set()
    findings: list[Finding] = []
    seen: set[tuple[str, int, str]] = set()

    for idx, line in enumerate(text.splitlines(), start=1):
        # 1. Sinks first (a sink on the same line as its assignment still counts).
        for sink in spec.sinks:
            if not sink.pattern.search(line):
                continue
            if spec.sanitizer.search(line):
                continue  # value sanitised on this line
            # Parameterised SQL: a placeholder in the query AND no string-building of
            # the tainted value into the query means it is a bound parameter, not
            # injection. (If there is ALSO concatenation, a real injection may be
            # present alongside a placeholder, so we do not skip.)
            if (sink.category == "sql_injection"
                    and _PARAM_PLACEHOLDER.search(line)
                    and not spec.concat.search(line)):
                continue
            inline_src = bool(spec.source.search(line))
            uses_tainted = any(v in tainted for v in _idents(line, spec.ident))
            if not (inline_src or uses_tainted):
                continue
            if sink.requires_concat and not (spec.concat.search(line) or inline_src or uses_tainted):
                continue
            key = (file, idx, sink.category)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                rule_id=sink.rule_id, category=sink.category, severity=sink.severity,
                file=file, line=idx, title=sink.title, detail=sink.detail,
                remediation=sink.remediation, confidence=sink.confidence,
                source=Source.DETERMINISTIC, cwe=sink.cwe,
            ))

        # 2. Propagate taint through assignments (after sink check, so a same-line
        #    assign+sink is still caught, and later lines see the new taint).
        m = spec.assign.search(line)
        if m and not re.search(r"[=!<>]=", line[: m.start(0) + len(m.group(1)) + 3]):
            lhs, rhs = m.group(1), m.group(2)
            if _rhs_is_tainted(rhs, spec, tainted):
                tainted.add(lhs)
            elif lhs in tainted and not _rhs_is_tainted(rhs, spec, tainted):
                # reassigned to something clean → clears taint
                tainted.discard(lhs)

    return findings
