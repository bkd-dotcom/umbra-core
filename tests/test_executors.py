"""Hermetic tests for the agent-agnostic executor layer.

No real agent is invoked and no network is touched: a FakeRunner stands in for
subprocess.run, and a real temp git repo captures the diff-from-git behavior.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from umbra_core import (
    AiderExecutor,
    ClaudeCodeExecutor,
    CodexExecutor,
    ExecutionResult,
    Executor,
    NullExecutor,
    available_executors,
    get_executor,
    resolve_available,
)


class FakeCompleted:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    """Scriptable stand-in for subprocess.run keyed by the first arg + subcommand."""

    def __init__(self, responses: dict[str, FakeCompleted], edit_file: Path | None = None, edit_text: str = ""):
        self.responses = responses
        self.calls: list[list[str]] = []
        self._edit_file = edit_file
        self._edit_text = edit_text

    def __call__(self, command, *args, **kwargs):
        self.calls.append(list(command))
        key = f"{command[0]}:{command[1] if len(command) > 1 else ''}"
        # Simulate the agent editing a file inside the checkout on the exec/print call.
        if self._edit_file is not None and command[0] in {"aider", "codex", "claude"} and command[1] in {"--message", "exec", "-p"}:
            self._edit_file.write_text(self._edit_text)
        return self.responses.get(key, FakeCompleted())


@pytest.fixture
def git_repo(tmp_path) -> Path:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.co"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    (tmp_path / "app.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=tmp_path, check=True)
    return tmp_path


# --- protocol / registry ----------------------------------------------------

def test_both_executors_satisfy_protocol():
    assert isinstance(AiderExecutor(), Executor)
    assert isinstance(CodexExecutor(), Executor)
    assert isinstance(ClaudeCodeExecutor(), Executor)


def test_registry_lists_and_resolves():
    assert set(available_executors()) == {"aider", "codex-cli", "claude-code", "none"}
    assert isinstance(get_executor("aider"), AiderExecutor)
    assert isinstance(get_executor("codex-cli"), CodexExecutor)
    assert isinstance(get_executor("claude-code"), ClaudeCodeExecutor)
    assert isinstance(get_executor("none"), NullExecutor)


def test_registry_unknown_raises():
    with pytest.raises(ValueError, match="Unknown executor"):
        get_executor("devin")


def test_resolve_available_none_when_disabled(monkeypatch):
    monkeypatch.delenv("UMBRA_ENABLE_AIDER", raising=False)
    monkeypatch.delenv("UMBRA_ENABLE_CODEX_CLI", raising=False)
    monkeypatch.delenv("UMBRA_ENABLE_CLAUDE_CODE", raising=False)
    # NullExecutor is always available but must NEVER be auto-selected.
    assert resolve_available(runner=FakeRunner({})) is None


def test_null_executor_makes_no_change_and_is_protocol():
    ex = NullExecutor()
    assert isinstance(ex, Executor)
    assert ex.available() is True
    assert ex.name == "none"
    result = ex.propose("review", Path("/tmp"))
    assert result.executor == "none"
    assert result.diff == ""
    assert result.files == []
    assert result.model_identity["model_evidence"] == "no-model"


# --- availability gating ----------------------------------------------------

def test_codex_unavailable_without_flag(monkeypatch):
    monkeypatch.delenv("UMBRA_ENABLE_CODEX_CLI", raising=False)
    assert CodexExecutor(runner=FakeRunner({})).available() is False


def test_aider_available_only_with_flag_and_cli(monkeypatch):
    runner = FakeRunner({"aider:--version": FakeCompleted(stdout="aider 0.86.2")})
    monkeypatch.delenv("UMBRA_ENABLE_AIDER", raising=False)
    assert AiderExecutor(runner=runner).available() is False
    monkeypatch.setenv("UMBRA_ENABLE_AIDER", "true")
    assert AiderExecutor(runner=FakeRunner({})).available() is False
    assert AiderExecutor(runner=runner).available() is True
    assert isinstance(resolve_available(["aider"], runner=runner), AiderExecutor)


def test_codex_model_allowlist_native(monkeypatch):
    # Native provider: only the built-in allowlist is accepted; a gateway model is dropped.
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    assert CodexExecutor(model="gpt-5.6-terra").model == "gpt-5.6-terra"
    assert CodexExecutor(model="gpt-5.5-gus").model is None


def test_codex_model_gateway_accepts_entitled_model(monkeypatch):
    # With a gateway base URL (e.g. IBM ICA), a safe custom model name is accepted.
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.nextgen-beta.ica.ibm.com/ica/v1")
    assert CodexExecutor(model="gpt-5.5-gus").model == "gpt-5.5-gus"


def test_codex_model_gateway_rejects_unsafe_name(monkeypatch):
    # Injection-safe: a model string with shell metacharacters is never accepted.
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.nextgen-beta.ica.ibm.com/ica/v1")
    assert CodexExecutor(model="bad;rm -rf /").model is None
    assert CodexExecutor(model="a b c").model is None


def test_codex_sandbox_default_and_override(monkeypatch):
    ex = CodexExecutor()
    monkeypatch.delenv("UMBRA_CODEX_SANDBOX", raising=False)
    assert ex._sandbox(read_only=True) == "read-only"
    assert ex._sandbox(read_only=False) == "workspace-write"
    # Operator override for CI runners where the OS sandbox can't initialize.
    monkeypatch.setenv("UMBRA_CODEX_SANDBOX", "danger-full-access")
    assert ex._sandbox(read_only=False) == "danger-full-access"
    # read-only path is unaffected by the override.
    assert ex._sandbox(read_only=True) == "read-only"


def test_codex_sandbox_override_rejects_invalid(monkeypatch):
    ex = CodexExecutor()
    monkeypatch.setenv("UMBRA_CODEX_SANDBOX", "bogus; rm -rf /")
    assert ex._sandbox(read_only=False) == "workspace-write"  # falls back to safe default


def test_codex_available_with_flag_and_version(monkeypatch):
    monkeypatch.setenv("UMBRA_ENABLE_CODEX_CLI", "true")
    runner = FakeRunner({"codex:--version": FakeCompleted(stdout="codex 0.9.0")})
    assert CodexExecutor(runner=runner).available() is True


def test_claude_unavailable_without_flag(monkeypatch):
    monkeypatch.delenv("UMBRA_ENABLE_CLAUDE_CODE", raising=False)
    assert ClaudeCodeExecutor(runner=FakeRunner({})).available() is False


def test_claude_available_with_flag_and_version(monkeypatch):
    monkeypatch.setenv("UMBRA_ENABLE_CLAUDE_CODE", "true")
    runner = FakeRunner({"claude:--version": FakeCompleted(stdout="2.1.215 (Claude Code)")})
    assert ClaudeCodeExecutor(runner=runner).available() is True


# --- propose: disabled result ----------------------------------------------

def test_disabled_result_is_honest(monkeypatch, git_repo):
    monkeypatch.delenv("UMBRA_ENABLE_CODEX_CLI", raising=False)
    res = CodexExecutor(runner=FakeRunner({})).propose("fix it", git_repo)
    assert res.executor == "codex-cli-disabled"
    assert res.diff == ""
    assert res.tests_passed is None


# --- propose: successful run captures diff from git -------------------------

def test_codex_propose_captures_diff(monkeypatch, git_repo):
    monkeypatch.setenv("UMBRA_ENABLE_CODEX_CLI", "true")
    runner = FakeRunner(
        {
            "codex:--version": FakeCompleted(stdout="codex 0.9.0"),
            "codex:exec": FakeCompleted(returncode=0, stdout="done"),
        },
        edit_file=git_repo / "app.py",
        edit_text="x = 2\n",
    )
    res = CodexExecutor(runner=runner).propose("bump x", git_repo)
    assert res.executor == "codex-cli"
    assert res.tests_passed is True
    assert "app.py" in res.files
    assert "x = 2" in res.diff
    assert res.model_identity["executor"] == "codex-cli"


def test_aider_propose_captures_diff_without_commit_authority(monkeypatch, git_repo):
    monkeypatch.setenv("UMBRA_ENABLE_AIDER", "true")
    runner = FakeRunner(
        {
            "aider:--version": FakeCompleted(stdout="aider 0.86.2"),
            "aider:--message": FakeCompleted(returncode=0, stdout="Bumped x to 2"),
        },
        edit_file=git_repo / "app.py",
        edit_text="x = 2\n",
    )
    result = AiderExecutor(runner=runner, model="openrouter/example-model").propose(
        "bump x",
        git_repo,
    )

    assert result.executor == "aider"
    assert "x = 2" in result.diff
    assert result.model_identity["model_configured"] == "openrouter/example-model"
    call = next(c for c in runner.calls if c[0] == "aider" and c[1] == "--message")
    assert "--no-auto-commits" in call
    assert "--no-suggest-shell-commands" in call
    assert "bump x" not in " ".join(result.command or [])


def test_aider_read_only_uses_dry_run(monkeypatch, git_repo):
    monkeypatch.setenv("UMBRA_ENABLE_AIDER", "true")
    runner = FakeRunner(
        {
            "aider:--version": FakeCompleted(stdout="aider 0.86.2"),
            "aider:--message": FakeCompleted(returncode=0, stdout="analysis"),
        }
    )
    AiderExecutor(runner=runner).propose("review", git_repo, read_only=True)
    call = next(c for c in runner.calls if c[0] == "aider" and c[1] == "--message")
    assert "--dry-run" in call


def test_claude_propose_captures_diff_and_parses_json(monkeypatch, git_repo):
    monkeypatch.setenv("UMBRA_ENABLE_CLAUDE_CODE", "true")
    runner = FakeRunner(
        {
            "claude:--version": FakeCompleted(stdout="2.1.215 (Claude Code)"),
            "claude:-p": FakeCompleted(
                returncode=0,
                stdout='{"result": "Bumped x to 2", "model": "claude-opus-4-8"}',
            ),
        },
        edit_file=git_repo / "app.py",
        edit_text="x = 2\n",
    )
    res = ClaudeCodeExecutor(runner=runner).propose("bump x", git_repo)
    assert res.executor == "claude-code"
    assert res.summary == "Bumped x to 2"
    assert "x = 2" in res.diff
    # resolved model was attested by the CLI JSON, so it is promoted honestly
    assert res.model_identity["model_resolved"] == "claude-opus-4-8"
    assert res.model_identity["model_evidence"] == "provider-attested"


# --- propose: failure is never dressed up as success ------------------------

def test_failed_run_reports_unavailable(monkeypatch, git_repo):
    monkeypatch.setenv("UMBRA_ENABLE_CLAUDE_CODE", "true")
    runner = FakeRunner(
        {
            "claude:--version": FakeCompleted(stdout="2.1.215"),
            "claude:-p": FakeCompleted(returncode=1, stderr="auth error"),
        }
    )
    res = ClaudeCodeExecutor(runner=runner).propose("fix", git_repo)
    assert res.executor == "unavailable"
    assert res.tests_passed is False


# --- trust boundary: claude runs with --bare (no CLAUDE.md auto-read) -------

def test_claude_run_uses_bare_and_blocks_push(monkeypatch, git_repo):
    monkeypatch.setenv("UMBRA_ENABLE_CLAUDE_CODE", "true")
    runner = FakeRunner(
        {
            "claude:--version": FakeCompleted(stdout="2.1.215"),
            "claude:-p": FakeCompleted(returncode=0, stdout='{"result":"ok"}'),
        }
    )
    ClaudeCodeExecutor(runner=runner).propose("fix", git_repo)
    exec_call = next(c for c in runner.calls if c[0] == "claude" and c[1] == "-p")
    assert "--bare" in exec_call
    joined = " ".join(exec_call)
    assert "git push" in joined  # appears inside a disallowed-tools entry
    assert "--disallowed-tools" in exec_call


# --- prompt is redacted from the replayable command -------------------------

def test_command_replay_redacts_prompt(monkeypatch, git_repo):
    monkeypatch.setenv("UMBRA_ENABLE_CODEX_CLI", "true")
    runner = FakeRunner(
        {
            "codex:--version": FakeCompleted(stdout="codex 0.9.0"),
            "codex:exec": FakeCompleted(returncode=0, stdout="done"),
        }
    )
    res = CodexExecutor(runner=runner).propose("secret mission text", git_repo)
    assert res.command is not None
    assert "secret mission text" not in " ".join(res.command)
    assert any("redacted" in part for part in res.command)


def test_execution_result_failed_factory():
    res = ExecutionResult.failed("p", "codex-cli", "boom")
    assert res.executor == "unavailable"
    assert res.tests_passed is False
    assert "boom" in (res.error or "")
