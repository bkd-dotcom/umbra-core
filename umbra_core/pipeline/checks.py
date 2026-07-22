"""Required-checks runner — executes a contract's validation commands, safely.

The Change Contract can declare ``required_checks`` (e.g. ``npm test``). Declaring
them is not enough: this module actually *runs* them and gates authority on the
result. But a repository is untrusted, and its ``.umbra/admission.yaml`` could
declare an arbitrary command — so execution is constrained on three axes and the
*enforcement level actually achieved* is recorded honestly (never overclaimed):

1. **Command allowlist.** Only known, server-owned check *profiles* run
   (``npm test``, ``npm ci``, ``pytest``, ``true``/``false`` for evals, …). A
   declared command that doesn't match a profile is reported ``blocked`` and never
   executed. This is the primary control — a repo cannot run ``curl … | sh``.
2. **Scrubbed environment.** The child gets a minimal env with every Umbra/OpenAI/
   GitHub/cloud secret stripped, so a check can't read credentials.
3. **Isolation, by the strongest tier that actually preflights.** A repo's build
   scripts (``npm install``) are hostile code, so we run them under the strongest
   available sandbox and record the tier truthfully — each wrapper is probed with
   ``… true`` first so we never label an isolation that didn't initialize:
     - ``sandboxed``        — bubblewrap: read-only OS, writable bind only on the
                              disposable checkout, private HOME/tmp, no network.
     - ``network-isolated`` — Linux ``unshare -rn`` (network cut; host filesystem —
                              not a full sandbox).
     - ``host-restricted``  — no working wrapper; allowlist + scrubbed env only.
   The report's ``enforcement`` field is the truthful status the UI/receipt shows.

CPU/memory/time limits are applied via a bounded timeout and (on POSIX) an
``resource``-based child preexec cap.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_CHECK_TIMEOUT_S = 300
_MEM_LIMIT_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB address-space cap (POSIX)

# Allowlisted check profiles. A declared command must match one of these patterns
# (after normalizing whitespace) to be executed. Kept deliberately small and
# dependency-manifest/test oriented — the profiles a governed remediation needs.
_ALLOWED_PROFILES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^true$"),
    re.compile(r"^false$"),
    re.compile(r"^npm (ci|install|test|run [a-z0-9:_-]+)( --[a-z-]+)*$", re.I),
    re.compile(r"^pnpm (install|test|run [a-z0-9:_-]+)$", re.I),
    re.compile(r"^yarn (install|test)$", re.I),
    re.compile(r"^pytest( -[a-zA-Z]+)*$"),
    re.compile(r"^python -m pytest( -[a-zA-Z]+)*$"),
    re.compile(r"^pip install -r requirements\.txt$"),
    re.compile(r"^go (build|test) \./\.\.\.$"),
    re.compile(r"^cargo (build|test)$"),
    re.compile(r"^make (test|check|lint)$"),
)

# Env-var name fragments whose values must never reach a check subprocess.
_SECRET_FRAGMENTS = ("OPENAI", "GITHUB", "UMBRA_FERNET", "UMBRA_SIGNING", "SESSION_SECRET",
                     "RESEND", "GOOGLE", "TOKEN", "SECRET", "PASSWORD", "API_KEY", "AWS", "GCP")

# Profiles that EXECUTE repository-supplied build code (install scripts, PEP517
# backends, arbitrary git/index URLs). Running these outside a real sandbox
# (host-restricted) means untrusted code runs with host filesystem + network, so
# authority is capped when they run un-sandboxed (see run_required_checks).
_CODE_EXECUTING_PROFILES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^npm (ci|install)", re.I),
    re.compile(r"^pnpm install", re.I),
    re.compile(r"^yarn install", re.I),
    re.compile(r"^pip install", re.I),
    re.compile(r"^go build", re.I),
    re.compile(r"^cargo build", re.I),
)


def _is_code_executing(cmd: str) -> bool:
    norm = " ".join((cmd or "").split())
    return any(p.match(norm) for p in _CODE_EXECUTING_PROFILES)


def _require_sandbox() -> bool:
    """When ``UMBRA_REQUIRE_SANDBOX`` is truthy, code-executing checks are refused
    (blocked) unless a real filesystem/network sandbox is available — fail closed
    instead of degrading to host-restricted."""
    return os.getenv("UMBRA_REQUIRE_SANDBOX", "").strip().lower() in {"1", "true", "yes"}


def _output_hash(text: str) -> str:
    return "sha256:" + hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


@dataclass
class CheckResult:
    command: str
    status: str  # "passed" | "failed" | "blocked" | "unavailable"
    exit_code: int | None
    output_hash: str | None
    detail: str

    def to_public(self) -> dict[str, Any]:
        return {"command": self.command, "status": self.status, "exit_code": self.exit_code, "output_hash": self.output_hash, "detail": self.detail}


@dataclass
class ChecksReport:
    results: list[CheckResult] = field(default_factory=list)
    ran: bool = False           # at least one required check actually executed
    all_passed: bool = False    # every declared check ran and passed (none blocked/failed/unavailable)
    enforcement: str = "none"   # "sandboxed" | "network-isolated" | "host-restricted" | "none"
    # True when a code-executing profile (npm/pip/yarn install, go/cargo build)
    # ran WITHOUT a real sandbox (host-restricted). The caller caps authority at
    # L1 in that case: untrusted build code executed with host fs+network.
    unsandboxed_code_execution: bool = False

    def to_public(self) -> dict[str, Any]:
        return {
            "ran": self.ran,
            "all_passed": self.all_passed,
            "enforcement": self.enforcement,
            "unsandboxed_code_execution": self.unsandboxed_code_execution,
            "results": [r.to_public() for r in self.results],
        }


def _profile_allowed(cmd: str) -> bool:
    norm = " ".join(cmd.split())
    return any(p.match(norm) for p in _ALLOWED_PROFILES)


def _scrubbed_env() -> dict[str, str]:
    """Minimal env with secrets removed — enough for npm/pytest to find a toolchain.

    This is an ALLOWLIST, not a denylist: only the toolchain vars below are copied
    from the parent environment, so nothing else (API keys, tokens, cloud creds)
    can leak into an untrusted check by construction. `_SECRET_FRAGMENTS` is used by
    the caller for defense-in-depth logging, not here.

    We deliberately do NOT copy ``PYTHONPATH`` / ``NODE_PATH`` — a poisoned value
    inherited from the parent could redirect module resolution inside the check.
    Tools find their own toolchain via ``PATH``.
    """
    keep = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SHELL")
    env: dict[str, str] = {k: os.environ[k] for k in keep if k in os.environ}
    # Defense-in-depth: drop any allowlisted var whose NAME still looks credential-like
    # (belt-and-suspenders against a future edit adding a risky name to `keep`).
    env = {k: v for k, v in env.items() if not any(frag in k.upper() for frag in _SECRET_FRAGMENTS)}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    # Signal to well-behaved tools that this is an isolated, offline check.
    env["CI"] = "1"
    env["npm_config_offline"] = "false"  # allow package resolution only if network exists
    return env


def _probe(argv: list[str]) -> bool:
    """Return True iff running ``argv`` (a sandbox wrapper around ``true``) actually
    exits 0. This is the preflight that prevents mislabeling: a wrapper that can't
    initialize (restricted namespaces, missing kernel support) exits non-zero, and
    we must NOT claim its enforcement tier."""
    try:
        r = subprocess.run(argv, capture_output=True, timeout=15, check=False)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def _bwrap_prefix(repo_path: Path) -> list[str]:
    """A bubblewrap filesystem sandbox: read-only OS, a writable bind only on the
    disposable checkout, a private/empty HOME and /tmp, and no network. This is the
    only tier we call a true 'sandbox' — the repo's own build scripts (npm install)
    cannot read the host home or write outside the checkout."""
    return [
        "bwrap",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/lib", "/lib",
        *(["--ro-bind", "/lib64", "/lib64"] if Path("/lib64").exists() else []),
        *(["--ro-bind", "/etc", "/etc"] if Path("/etc").exists() else []),
        "--bind", str(repo_path), str(repo_path),
        "--tmpfs", "/tmp",
        "--tmpfs", str(Path.home()) if str(Path.home()) not in ("/", "") else "/root",
        "--dev", "/dev",
        "--proc", "/proc",
        "--unshare-all",           # new user/net/pid/ipc/uts/cgroup namespaces
        "--die-with-parent",
        "--chdir", str(repo_path),
    ]


def _resolve_enforcement(repo_path: Path) -> tuple[list[str], str]:
    """Pick the strongest isolation that PREFLIGHTS successfully, and return
    (argv-prefix, honest-enforcement-tier):

    - ``sandboxed``       — bubblewrap filesystem+network sandbox (probed).
    - ``network-isolated``— Linux ``unshare -rn`` (network cut; host filesystem).
    - ``host-restricted`` — no working wrapper; allowlist + scrubbed env only.

    Each candidate is probed with ``… true`` first, so we never label a tier whose
    wrapper doesn't actually initialize in this environment.
    """
    if shutil.which("bwrap"):
        # Probe with a trivial sandbox (don't bind the repo for the probe).
        if _probe(["bwrap", "--ro-bind", "/usr", "/usr", "--ro-bind", "/bin", "/bin",
                   *(["--ro-bind", "/lib", "/lib"] if Path("/lib").exists() else []),
                   *(["--ro-bind", "/lib64", "/lib64"] if Path("/lib64").exists() else []),
                   "--tmpfs", "/tmp", "--unshare-all", "--die-with-parent", "true"]):
            return _bwrap_prefix(repo_path), "sandboxed"
    if shutil.which("unshare") and _probe(["unshare", "-r", "-n", "true"]):
        return (["unshare", "-r", "-n"], "network-isolated")
    return ([], "host-restricted")


def _preexec_limits():  # pragma: no cover - POSIX-only, exercised at runtime
    """Cap CPU time and address space for the child (POSIX)."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (_CHECK_TIMEOUT_S, _CHECK_TIMEOUT_S))
        resource.setrlimit(resource.RLIMIT_AS, (_MEM_LIMIT_BYTES, _MEM_LIMIT_BYTES))
    except Exception:  # noqa: BLE001 - limits are best-effort
        pass


def run_required_checks(repo_path: Path | str, commands: list[str]) -> ChecksReport:
    """Run each declared check under the allowlist + scrubbed env + the strongest
    isolation tier that preflights successfully.

    ``ran`` is True iff at least one command executed; ``all_passed`` is True iff
    every declared command ran and passed (a blocked/unavailable/failed check makes
    it False). ``enforcement`` records the isolation *actually achieved and probed*
    — ``sandboxed`` (bubblewrap fs+net), ``network-isolated`` (unshare net only), or
    ``host-restricted``. Never raises.
    """
    root = Path(repo_path).resolve()
    report = ChecksReport()
    if not commands:
        return report

    prefix, enforcement = _resolve_enforcement(root)
    report.enforcement = enforcement
    env = _scrubbed_env()
    preexec = _preexec_limits if os.name == "posix" else None

    executed_any = False
    every_ok = True
    for command in commands:
        cmd = (command or "").strip()
        if not cmd:
            continue
        # 1. Allowlist — a non-profile command is refused, never executed.
        if not _profile_allowed(cmd):
            report.results.append(CheckResult(cmd, "blocked", None, None, "Command is not an allowlisted check profile; refused (not executed)."))
            every_ok = False
            continue
        argv = shlex.split(cmd)
        if not shutil.which(argv[0]):
            report.results.append(CheckResult(cmd, "unavailable", None, None, f"`{argv[0]}` is not available in this environment."))
            every_ok = False
            continue
        # Strict sandbox mode: refuse to execute repo-supplied build code when no
        # real sandbox is available (fail closed instead of degrading to host).
        if _require_sandbox() and _is_code_executing(cmd) and enforcement != "sandboxed":
            report.results.append(CheckResult(
                cmd, "blocked", None, None,
                f"UMBRA_REQUIRE_SANDBOX is set and no filesystem/network sandbox is available "
                f"(enforcement: {enforcement}); refusing to run repo-supplied build code.",
            ))
            every_ok = False
            continue
        try:
            completed = subprocess.run(
                [*prefix, *argv], cwd=root, text=True, capture_output=True,
                timeout=_CHECK_TIMEOUT_S, check=False, env=env, preexec_fn=preexec,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            report.results.append(CheckResult(cmd, "unavailable", None, None, f"Could not run `{cmd}`: {exc}"))
            every_ok = False
            continue
        executed_any = True
        combined = (completed.stdout or "") + (completed.stderr or "")
        passed = completed.returncode == 0
        every_ok = every_ok and passed
        # Flag when repo-supplied build code executed outside a real sandbox.
        if _is_code_executing(cmd) and enforcement not in ("sandboxed",):
            report.unsandboxed_code_execution = True
            logging.getLogger("umbra.checks").warning(
                "Check %r executes repo-supplied build code but ran under %r (no fs/net "
                "sandbox). Authority will be capped at L1.", cmd, enforcement,
            )
        report.results.append(CheckResult(cmd, "passed" if passed else "failed", completed.returncode, _output_hash(combined), f"`{cmd}` exited {completed.returncode}."))

    report.ran = executed_any
    report.all_passed = executed_any and every_ok
    return report
