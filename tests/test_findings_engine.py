"""Tests for the layered detection engine (umbra_core.pipeline.findings).

Covers three properties that matter for parity with LLM scanners:
1. DETECTION: the deterministic floor finds the OWASP-class vulns the competitors
   detect (SQLi, command injection, unsafe deser, path traversal, XSS, weak crypto,
   insecure randomness, eval, debug mode, hardcoded secrets) — via a fixture that
   mirrors the head-to-head benchmark.
2. ZERO FALSE POSITIVES: safe equivalents (parameterised queries, arg-list
   subprocess, escaped output, secure randomness) produce no findings.
3. LAYER CONTRACT: semgrep/triage are optional and recorded honestly; the LLM
   triage layer can only drop/annotate/lower-confidence, never strengthen.
"""
from __future__ import annotations

from pathlib import Path

from umbra_core.pipeline.findings import (
    Finding,
    Severity,
    Source,
    scan_repository,
    scan_source,
    to_sarif,
    triage_findings,
)
from umbra_core.pipeline.findings.fetch import _looks_like_url

# --- fixtures ---------------------------------------------------------------

VULN_PY = '''
import os, sqlite3, subprocess, pickle, hashlib, flask

SECRET_KEY = "sk-live-1234567890abcdefghij"
DB_PASSWORD = "SuperSecretP@ssw0rd!"

def get_user():
    user_id = flask.request.args.get("id")
    conn = sqlite3.connect("app.db"); cur = conn.cursor()
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    cur.execute(query)
    return str(cur.fetchall())

def ping():
    host = flask.request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)

def load():
    data = flask.request.args.get("data")
    return str(pickle.loads(bytes.fromhex(data)))

def render():
    name = flask.request.args.get("name")
    return "<h1>Hello " + name + "</h1>"

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def run_code(expr):
    return eval(expr)

def read_file():
    fname = flask.request.args.get("file")
    with open("/var/data/" + fname) as f:
        return f.read()

if __name__ == "__main__":
    flask.Flask(__name__).run(host="0.0.0.0", debug=True)
'''

VULN_JS = '''
const JWT_SECRET = "hardcoded-jwt-secret-value-here";
app.get("/exec", (req, res) => {
  const { exec } = require("child_process");
  exec("ls " + req.query.dir, (e, out) => res.send(out));
});
app.get("/token", (req, res) => { res.send(Math.random().toString(36)); });
app.get("/html", (req, res) => { res.send("<div>" + req.query.msg + "</div>"); });
'''

SAFE_PY = '''
import sqlite3, subprocess, hashlib, secrets
from markupsafe import escape

def get_user(user_id):
    cur = sqlite3.connect("app.db").cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchall()

def ping(host):
    return subprocess.check_output(["ping", "-c", "1", host])

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def render(name):
    return "<h1>Hello " + escape(name) + "</h1>"

def token():
    return secrets.token_hex(16)

API_URL = "https://api.example.com"
'''

SAFE_JS = '''
const crypto = require("crypto");
function token() { return crypto.randomBytes(16).toString("hex"); }
const API_URL = "https://api.example.com";
'''


def _write(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return tmp_path


# --- 1. detection -----------------------------------------------------------


def test_detects_all_vuln_classes(tmp_path):
    _write(tmp_path, {"src/app.py": VULN_PY, "src/server.js": VULN_JS})
    report = scan_repository(tmp_path)
    cats = {f.category for f in report.findings}
    expected = {
        "hardcoded_secret", "sql_injection", "command_injection",
        "insecure_deserialization", "xss", "weak_crypto", "code_injection",
        "path_traversal", "debug_enabled", "insecure_randomness",
    }
    missing = expected - cats
    assert not missing, f"missed vuln classes: {missing} (found {cats})"


def test_python_taint_through_intermediate_variable(tmp_path):
    # SQLi/path-traversal here flow through one intermediate variable; taint
    # tracking must still catch them (the naive inline check would miss these).
    _write(tmp_path, {"app.py": VULN_PY})
    report = scan_repository(tmp_path)
    cats = {f.category for f in report.findings}
    assert "sql_injection" in cats
    assert "path_traversal" in cats


def test_findings_carry_cwe_and_source(tmp_path):
    _write(tmp_path, {"app.py": VULN_PY})
    report = scan_repository(tmp_path)
    sqli = next(f for f in report.findings if f.category == "sql_injection")
    assert sqli.cwe == "CWE-89"
    assert sqli.source == Source.DETERMINISTIC
    assert 0.0 < sqli.confidence <= 1.0


# --- 2. zero false positives ------------------------------------------------


def test_no_false_positives_on_safe_code(tmp_path):
    _write(tmp_path, {"safe.py": SAFE_PY, "safe.js": SAFE_JS})
    report = scan_repository(tmp_path)
    assert report.findings == [], (
        "safe code produced false positives: "
        + ", ".join(f"{f.file}:{f.line} {f.rule_id}" for f in report.findings)
    )


def test_placeholder_secret_not_flagged(tmp_path):
    _write(tmp_path, {"config.py": 'API_KEY = "your-api-key-here-example"\n'})
    report = scan_repository(tmp_path)
    assert not [f for f in report.findings if f.category == "hardcoded_secret"]


def test_fixture_paths_skip_secret_rule(tmp_path):
    _write(tmp_path, {"tests/fixtures/data.py": 'TOKEN = "abcdef1234567890xyz"\n'})
    report = scan_repository(tmp_path)
    assert not [f for f in report.findings if f.category == "hardcoded_secret"]


# --- 3. layer contract ------------------------------------------------------


def test_layers_recorded_honestly(tmp_path):
    _write(tmp_path, {"app.py": VULN_PY})
    report = scan_repository(tmp_path)  # no semgrep, no triage
    assert Source.DETERMINISTIC.value in report.layers
    # semgrep/triage not requested → recorded as unavailable, never silently claimed
    assert Source.LLM_TRIAGE.value in report.layers_unavailable


def test_triage_can_drop_false_positive():
    f = Finding("py.sql_injection", "sql_injection", Severity.HIGH, "a.py", 1,
                "t", "d", "r", 0.9, Source.DETERMINISTIC, "CWE-89")

    def triage(_prompt: str) -> str:
        return '{"verdicts": [{"index": 0, "false_positive": true, "confidence": 0.1}]}'

    out, ran = triage_findings([f], triage)
    assert ran is True
    assert out == []  # dropped as a false positive


def test_triage_cannot_raise_confidence():
    f = Finding("py.sql_injection", "sql_injection", Severity.HIGH, "a.py", 1,
                "t", "d", "r", 0.6, Source.DETERMINISTIC, "CWE-89")

    def triage(_prompt: str) -> str:
        # Model tries to claim higher confidence than the deterministic floor.
        return '{"verdicts": [{"index": 0, "false_positive": false, "confidence": 0.99}]}'

    out, ran = triage_findings([f], triage)
    assert ran is True
    assert out[0].confidence <= 0.6  # floor confidence is never raised by the model


def test_triage_absent_is_noop():
    f = Finding("py.eval", "code_injection", Severity.HIGH, "a.py", 1, "t", "d", "r", 0.8)
    out, ran = triage_findings([f], None)
    assert ran is False and out == [f]


def test_triage_never_crashes_scan():
    f = Finding("py.eval", "code_injection", Severity.HIGH, "a.py", 1, "t", "d", "r", 0.8)

    def broken(_prompt: str) -> str:
        raise RuntimeError("model down")

    out, ran = triage_findings([f], broken)
    assert ran is False and out == [f]  # failure degrades to pass-through


# --- report shape -----------------------------------------------------------


def test_report_to_public_is_json_serialisable(tmp_path):
    import json
    _write(tmp_path, {"app.py": VULN_PY})
    report = scan_repository(tmp_path)
    blob = json.dumps(report.to_public())
    assert '"sql_injection"' in blob
    assert report.highest_severity == Severity.HIGH


def test_scan_source_single_file():
    findings = scan_source("x.py", "eval(user_input)\n")
    assert any(f.category == "code_injection" for f in findings)


# --- extended rule classes (SSRF / SSTI / JWT / Django / NoSQL) --------------


def _cats(src: str, fname: str = "x.py") -> set[str]:
    return {f.category for f in scan_source(fname, src)}


def test_detects_ssrf():
    src = (
        "import requests, flask\n"
        "app = flask.Flask(__name__)\n"
        "@app.route('/f')\n"
        "def f():\n"
        "    url = flask.request.args.get('url')\n"
        "    return requests.get(url).text\n"
    )
    assert "ssrf" in _cats(src)


def test_detects_ssti():
    src = (
        "import flask\n"
        "from flask import render_template_string\n"
        "def g():\n"
        "    name = flask.request.args.get('name')\n"
        "    return render_template_string('<h1>' + name + '</h1>')\n"
    )
    assert "template_injection" in _cats(src)


def test_detects_jwt_no_verify():
    src = "import jwt\ndef d(t):\n    return jwt.decode(t, options={'verify_signature': False})\n"
    assert "auth_bypass" in _cats(src)


def test_detects_jwt_alg_none():
    src = "import jwt\ndef d(t, k):\n    return jwt.decode(t, k, algorithms=['none'])\n"
    assert "auth_bypass" in _cats(src)


def test_detects_django_extra_sqli():
    src = (
        "def search(request):\n"
        "    q = request.GET.get('q')\n"
        "    return Product.objects.extra(where=[\"name = '%s'\" % q])\n"
    )
    assert "sql_injection" in _cats(src)


def test_detects_nosql_injection_js():
    src = (
        "app.post('/login', async (req, res) => {\n"
        "  const u = await db.collection('users').findOne({\n"
        "    username: req.body.username, password: req.body.password });\n"
        "  res.send(u ? 'ok' : 'no');\n"
        "});\n"
    )
    assert "nosql_injection" in _cats(src, "login.js")


# --- new SAFE cases must NOT trip the new rules -----------------------------


def test_allowlist_validated_input_is_not_flagged(tmp_path):
    src = (
        "import subprocess, flask\n"
        "app = flask.Flask(__name__)\n"
        "ALLOWED = {'status', 'uptime'}\n"
        "@app.route('/c')\n"
        "def c():\n"
        "    name = flask.request.args.get('name')\n"
        "    if name not in ALLOWED:\n"
        "        flask.abort(400)\n"
        "    return subprocess.check_output(['/bin/tool', name])\n"
    )
    # arg-list subprocess (no shell) → no command_injection regardless of allowlist
    assert "command_injection" not in _cats(src)


def test_public_constant_not_flagged_as_secret():
    src = 'PUBLIC_KEY_ID = "pk_publishable_example_00000000"\n'
    assert "hardcoded_secret" not in _cats(src)


# --- SARIF export -----------------------------------------------------------


def test_sarif_export_is_valid_shape(tmp_path):
    _write(tmp_path, {"app.py": VULN_PY})
    report = scan_repository(tmp_path)
    doc = to_sarif(report, tool_version="1.2.3")
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "umbra-core"
    assert run["tool"]["driver"]["version"] == "1.2.3"
    assert len(run["results"]) == len(report.findings)
    # every result references a rule and a location
    for r in run["results"]:
        assert r["ruleId"]
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_empty_report(tmp_path):
    _write(tmp_path, {"safe.py": SAFE_PY})
    doc = to_sarif(scan_repository(tmp_path))
    assert doc["runs"][0]["results"] == []


# --- remote-scan URL detection ----------------------------------------------


def test_url_detection():
    assert _looks_like_url("https://github.com/owner/repo.git")
    assert _looks_like_url("git@github.com:owner/repo.git")
    assert _looks_like_url("https://github.com/owner/repo")
    assert not _looks_like_url("/local/path/to/repo")
    assert not _looks_like_url("./relative")


# --- cross-file / interprocedural taint -------------------------------------


def test_cross_file_taint_detected(tmp_path):
    _write(tmp_path, {
        "views.py": (
            "import flask\nfrom db import run_query\n"
            "app = flask.Flask(__name__)\n"
            "@app.route('/f')\n"
            "def f():\n"
            "    term = flask.request.args.get('q')\n"
            "    return str(run_query(term))\n"
        ),
        "db.py": (
            "import sqlite3\n"
            "def run_query(term):\n"
            "    return sqlite3.connect('d').cursor().execute("
            "\"SELECT * FROM t WHERE n = '\" + term + \"'\").fetchall()\n"
        ),
    })
    report = scan_repository(tmp_path)
    xfile = [f for f in report.findings if f.category == "sql_injection" and f.file == "db.py"]
    assert xfile, "cross-file SQL injection was not detected"
    assert xfile[0].rule_id.startswith("xfile.")


def test_cross_file_no_fp_on_untainted_call(tmp_path):
    # A constant passed into the same helper must NOT be flagged.
    _write(tmp_path, {
        "caller.py": (
            "from helper import run_query\n"
            "def go():\n"
            "    return run_query('static_value')\n"
        ),
        "helper.py": (
            "import sqlite3\n"
            "def run_query(term):\n"
            "    return sqlite3.connect('d').cursor().execute("
            "\"SELECT * FROM t WHERE n = '\" + term + \"'\").fetchall()\n"
        ),
    })
    report = scan_repository(tmp_path)
    xfile = [f for f in report.findings if f.rule_id.startswith("xfile.")]
    assert not xfile, f"false positive cross-file finding on constant input: {xfile}"


def test_cross_file_can_be_disabled(tmp_path):
    _write(tmp_path, {
        "views.py": (
            "import flask\nfrom db import q\n"
            "def f():\n    t = flask.request.args.get('x')\n    return q(t)\n"
        ),
        "db.py": (
            "import sqlite3\n"
            "def q(t):\n    return sqlite3.connect('d').cursor().execute('SELECT '+t)\n"
        ),
    })
    report = scan_repository(tmp_path, cross_file=False)
    assert not [f for f in report.findings if f.rule_id.startswith("xfile.")]


# --- multi-language rules ---------------------------------------------------


def test_multilang_go():
    src = 'rows, _ := db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %s", id))\n'
    assert "sql_injection" in _cats(src, "main.go")


def test_multilang_java():
    src = 'stmt.executeQuery("SELECT * FROM u WHERE id = " + id);\n'
    assert "sql_injection" in _cats(src, "Dao.java")


def test_multilang_ruby():
    src = 'system("tar czf b.tgz #{params[:dir]}")\n'
    assert "command_injection" in _cats(src, "ops.rb")


def test_multilang_php():
    src = '<?php mysqli_query($c, "SELECT * FROM u WHERE id = " . $_GET["id"]);\n'
    assert "sql_injection" in _cats(src, "user.php")


def test_multilang_csharp():
    src = 'var cmd = new SqlCommand("SELECT * FROM U WHERE Id = " + id);\n'
    assert "sql_injection" in _cats(src, "Repo.cs")


def test_multilang_safe_php_prepared_not_flagged():
    src = '<?php $stmt = $pdo->prepare("SELECT * FROM u WHERE id = ?"); $stmt->execute([$_GET["id"]]);\n'
    assert "sql_injection" not in _cats(src, "safe.php")


# --- multi-variable taint flow across languages -----------------------------


def test_lang_taint_go_multivar():
    src = ('id := r.URL.Query().Get("id")\n'
           'q := "SELECT * FROM u WHERE id = " + id\n'
           'rows, _ := db.Query(q)\n')
    assert "sql_injection" in _cats(src, "main.go")


def test_lang_taint_java_multivar():
    src = ('String id = req.getParameter("id");\n'
           'String q = "SELECT * FROM u WHERE id = " + id;\n'
           'stmt.executeQuery(q);\n')
    assert "sql_injection" in _cats(src, "Dao.java")


def test_lang_taint_php_multivar():
    src = ('<?php $id = $_GET["id"];\n'
           '$q = "SELECT * FROM u WHERE id = " . $id;\n'
           'mysqli_query($conn, $q);\n')
    assert "sql_injection" in _cats(src, "user.php")


def test_lang_taint_ruby_multivar():
    src = ('name = params[:name]\n'
           'q = "SELECT * FROM u WHERE n = #{name}"\n'
           'ActiveRecord::Base.connection.execute(q)\n')
    assert "sql_injection" in _cats(src, "app.rb")


def test_lang_taint_csharp_multivar():
    src = ('var id = Request.Query["id"];\n'
           'var q = "SELECT * FROM U WHERE Id = " + id;\n'
           'var cmd = new SqlCommand(q);\n')
    assert "sql_injection" in _cats(src, "Repo.cs")


def test_lang_taint_go_parameterized_is_safe():
    src = ('id := r.URL.Query().Get("id")\n'
           'rows, _ := db.Query("SELECT * FROM u WHERE id = $1", id)\n')
    assert "sql_injection" not in _cats(src, "safe.go")


def test_lang_taint_sanitized_input_is_safe():
    # parseInt sanitizes → no SQLi even though it reaches a query
    src = ('int id = Integer.parseInt(req.getParameter("id"));\n'
           'String q = "SELECT * FROM u WHERE id = " + id;\n'
           'stmt.executeQuery(q);\n')
    assert "sql_injection" not in _cats(src, "Safe.java")


def test_lang_taint_untainted_not_flagged():
    # constant, no user input → nothing
    src = ('q := "SELECT * FROM u WHERE id = 1"\n'
           'rows, _ := db.Query(q)\n')
    assert _cats(src, "const.go") == set()


# --- fusion: finding -> governed fix -> receipt-ready report -----------------


def _git_repo(tmp_path, files: dict[str, str]):
    import subprocess
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=tmp_path, check=True)
    return tmp_path


def test_fusion_proposes_governed_fix(tmp_path):
    from umbra_core.pipeline.findings import propose_fix, scan_repository

    _git_repo(tmp_path, {"app.py": (
        "import os, flask\napp = flask.Flask(__name__)\n"
        "@app.route('/r')\ndef r():\n"
        "    cmd = flask.request.args.get('cmd')\n"
        "    os.system('tool ' + cmd)\n    return 'ok'\n"
    )})
    report = scan_repository(tmp_path, cross_file=False)
    finding = next(f for f in report.findings if f.category == "command_injection")
    proposal = propose_fix(tmp_path, finding)
    # A mission was derived and the admission pipeline ran.
    assert finding.file in proposal.mission
    assert proposal.report is not None
    # No live executor → no change → capped at analyze, never merges.
    assert proposal.report.authority_level <= 1
    assert proposal.to_public()["auto_merge"] is False


def test_fusion_seals_a_receipt(tmp_path):
    from umbra_core.pipeline.findings import propose_fix, scan_repository

    _git_repo(tmp_path, {"app.py": (
        "import os, flask\napp = flask.Flask(__name__)\n"
        "@app.route('/r')\ndef r():\n"
        "    cmd = flask.request.args.get('cmd')\n"
        "    os.system('tool ' + cmd)\n    return 'ok'\n"
    )})
    report = scan_repository(tmp_path, cross_file=False)
    finding = report.findings[0]
    proposal = propose_fix(tmp_path, finding, sign_receipt=True)
    assert proposal.receipt is not None
    assert "canonical_hash" in proposal.receipt
    # branch_pr_ready reflects earned authority (analyze here → not ready)
    assert proposal.branch_pr_ready == (proposal.report.authority_level >= 2)


def test_fusion_agent_none_is_deterministic(tmp_path):
    from umbra_core.pipeline.findings import propose_fix, scan_repository

    _git_repo(tmp_path, {"app.py": (
        "import os, flask\n@app.route('/r')\ndef r():\n"
        "    cmd = flask.request.args.get('cmd')\n    os.system('t ' + cmd)\n"
    )})
    report = scan_repository(tmp_path, cross_file=False)
    # Explicit deterministic agent → no change, capped at analyze, never errors.
    proposal = propose_fix(tmp_path, report.findings[0], agent="none")
    assert proposal.report.authority_level <= 1
    assert proposal.to_public()["auto_merge"] is False


# --- bring-your-own-key: secret redaction never leaks a credential ----------


def test_redaction_scrubs_credential_shapes():
    from umbra_core.pipeline.findings.secret_redaction import redact_secrets

    cases = [
        ('api_key = "sk-live-abc123def456ghi789jkl"', "sk-"),
        ('ANTHROPIC_API_KEY="sk-ant-abcdefghij1234567890"', "sk-ant-"),
        ("token: ghp_abcdefghij1234567890ABCD", "ghp_"),
        ("aws = AKIAIOSFODNN7EXAMPLE", "AKIA"),
    ]
    for text, shape in cases:
        out = redact_secrets(text)
        assert shape not in out, f"credential shape leaked: {out}"
        assert "REDACTED" in out


def test_redaction_leaves_normal_code_untouched():
    from umbra_core.pipeline.findings.secret_redaction import redact_secrets

    for src in ("x = y + 1", "def query(uid): return db.execute(sql, uid)",
                "url = 'https://api.example.com/v1'"):
        assert redact_secrets(src) == src


def test_redaction_handles_none():
    from umbra_core.pipeline.findings.secret_redaction import redact_secrets
    assert redact_secrets(None) is None
    assert redact_secrets("") == ""


def test_check_env_is_allowlist_no_api_keys_leak(monkeypatch):
    """The required-check subprocess env is an allowlist — no executor key can reach
    it by construction, regardless of what is set in the parent environment."""
    from umbra_core.pipeline.checks import _scrubbed_env

    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-not-leak")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-should-not-leak")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_should_not_leak")
    env = _scrubbed_env()
    joined = " ".join(f"{k}={v}" for k, v in env.items())
    assert "should-not-leak" not in joined and "should_not_leak" not in joined
    for k in env:
        assert not any(frag in k.upper() for frag in ("OPENAI", "ANTHROPIC", "API_KEY", "TOKEN"))


def test_fusion_mission_is_bounded_to_finding():
    from umbra_core.pipeline.findings import Finding, Severity, mission_for_finding
    from umbra_core.pipeline.findings.model import Source

    f = Finding("py.sql_injection", "sql_injection", Severity.HIGH, "db.py", 12,
                "t", "d", "Use parameterised queries.", 0.9, Source.DETERMINISTIC, "CWE-89")
    mission = mission_for_finding(f)
    assert "db.py:12" in mission
    assert "only what is necessary" in mission


def test_fusion_orders_by_severity(tmp_path):
    from umbra_core.pipeline.findings import propose_fixes, scan_repository

    _git_repo(tmp_path, {"app.py": (
        "import os, hashlib, flask\napp = flask.Flask(__name__)\n"
        "SECRET = 'sk-live-abc123def456ghi789jkl'\n"
        "@app.route('/r')\ndef r():\n"
        "    cmd = flask.request.args.get('cmd')\n"
        "    os.system('t ' + cmd)\n    return 'ok'\n"
    )})
    report = scan_repository(tmp_path, cross_file=False)
    proposals = propose_fixes(tmp_path, report.findings, max_fixes=5)
    assert len(proposals) >= 1
    # highest severity first
    sevs = [p.finding.severity.rank for p in proposals]
    assert sevs == sorted(sevs, reverse=True)


# --- cross-file taint for non-Python languages ------------------------------


def _scan_files(tmp_path, files: dict[str, str]):
    from umbra_core.pipeline.findings import scan_repository
    for rel, content in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return scan_repository(tmp_path)


def test_crossfile_go(tmp_path):
    report = _scan_files(tmp_path, {
        "handler.go": ('package main\nimport "net/http"\n'
                       'func handler(db *DB, r *http.Request) {\n'
                       '    id := r.URL.Query().Get("id")\n    lookup(db, id)\n}\n'),
        "store.go": ('package main\nfunc lookup(db *DB, name string) {\n'
                     '    q := "SELECT * FROM u WHERE n = " + name\n    db.Query(q)\n}\n'),
    })
    assert any(f.file == "store.go" and f.category == "sql_injection" for f in report.findings)


def test_crossfile_java(tmp_path):
    report = _scan_files(tmp_path, {
        "Controller.java": ('public class Controller {\n'
                            '  void handle(Dao dao, javax.servlet.http.HttpServletRequest req) throws Exception {\n'
                            '    String id = req.getParameter("id");\n    dao.find(id);\n  }\n}\n'),
        "Dao.java": ('public class Dao {\n  public void find(String id) throws Exception {\n'
                     '    String q = "SELECT * FROM u WHERE id = " + id;\n    stmt.executeQuery(q);\n  }\n}\n'),
    })
    assert any(f.file == "Dao.java" and f.category == "sql_injection" for f in report.findings)


def test_crossfile_php(tmp_path):
    report = _scan_files(tmp_path, {
        "index.php": '<?php\n$id = $_GET["id"];\nrun_query($id);\n',
        "db.php": ('<?php\nfunction run_query($id) {\n'
                   '    $q = "SELECT * FROM u WHERE id = " . $id;\n    mysqli_query($conn, $q);\n}\n'),
    })
    assert any(f.file == "db.php" and f.category == "sql_injection" for f in report.findings)


def test_crossfile_ruby(tmp_path):
    report = _scan_files(tmp_path, {
        "controller.rb": ('class Controller\n  def handle(dao, params)\n'
                          '    id = params[:id]\n    dao.find(id)\n  end\nend\n'),
        "dao.rb": ('class Dao\n  def find(id)\n'
                   '    q = "SELECT * FROM u WHERE id = #{id}"\n'
                   '    ActiveRecord::Base.connection.execute(q)\n  end\nend\n'),
    })
    assert any(f.file == "dao.rb" and f.category == "sql_injection" for f in report.findings)


def test_crossfile_csharp(tmp_path):
    report = _scan_files(tmp_path, {
        "Controller.cs": ('public class Controller {\n'
                          '  public void Handle(Dao dao, Microsoft.AspNetCore.Http.HttpRequest request) {\n'
                          '    var id = request.Query["id"];\n    dao.Find(id);\n  }\n}\n'),
        "Dao.cs": ('public class Dao {\n  public void Find(string id) {\n'
                   '    var q = "SELECT * FROM U WHERE Id = " + id;\n    var cmd = new SqlCommand(q);\n  }\n}\n'),
    })
    assert any(f.file == "Dao.cs" and f.category == "sql_injection" for f in report.findings)


def test_crossfile_lang_constant_arg_no_fp(tmp_path):
    # Caller passes a constant into a parameterised callee → no cross-file finding.
    from umbra_core.pipeline.findings.lang_crossfile import analyze_repo_taint_multilang
    files = {
        "main.go": 'package main\nfunc boot(db *DB) {\n    lookup(db, "healthcheck")\n}\n',
        "repo.go": ('package main\nfunc lookup(db *DB, name string) {\n'
                    '    db.Query("SELECT * FROM s WHERE n = $1", name)\n}\n'),
    }
    findings = analyze_repo_taint_multilang(files)
    assert not [f for f in findings if "xfile" in f.rule_id]


# --- optional tree-sitter backend ------------------------------------------


def test_treesitter_graceful_when_absent(tmp_path):
    # With use_treesitter=True, the scan must not error whether or not the optional
    # packages are installed; the layer is recorded honestly.
    from umbra_core.pipeline.findings import scan_repository
    (tmp_path / "a.go").write_text('package main\nfunc h(db *DB, r *R) {\n'
                                   '    db.Query("SELECT " + r.URL.Query().Get("id"))\n}\n')
    report = scan_repository(tmp_path, use_treesitter=True)
    assert "treesitter" in report.layers or "treesitter" in report.layers_unavailable


def test_js_ssrf_detection_and_safe_case(tmp_path):
    vuln_code = """
    app.get("/fetch", async (req, res) => {
        const url = req.query.target;
        await fetch(url);
    });
    """
    safe_code = """
    app.get("/fetch", async (req, res) => {
        const url = "https://api.example.com/data";
        await fetch(url);
    });
    """
    (tmp_path / "vuln.js").write_text(vuln_code)
    (tmp_path / "safe.js").write_text(safe_code)

    report = scan_repository(tmp_path)

    vuln_ssrf = [f for f in report.findings if f.file == "vuln.js" and f.category == "ssrf"]
    assert len(vuln_ssrf) >= 1
    assert vuln_ssrf[0].cwe == "CWE-918"

    safe_ssrf = [f for f in report.findings if f.file == "safe.js" and f.category == "ssrf"]
    assert len(safe_ssrf) == 0
