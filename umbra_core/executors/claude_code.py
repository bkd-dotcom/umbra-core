"""Claude Code executor — adapts the ``claude`` CLI to the Executor protocol.

This is the proof that umbra-core is agent-agnostic: Claude Code is governed by
the *same* admission pipeline as Codex. It runs headless (``-p``) inside a
disposable checkout with:

- ``--bare`` — skips CLAUDE.md auto-discovery, so the agent does not silently
  ingest untrusted repository instruction files. This reinforces Umbra's trust
  boundary: the agent can't read manipulation Umbra hasn't vetted.
- ``--disallowed-tools`` — git push/commit/merge and other authority-bearing
  commands are refused at the tool layer; the agent cannot self-grant authority.
- the diff is recomputed from ``git`` on the final tree, so the signed change
  reflects only the agent's real edits.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .base import ExecutionResult
from ._shared import (
    Runner,
    bounded_prompt,
    changed_files,
    reason_prompt,
    sanitize_paths,
    unified_diff,
)

logger = logging.getLogger("umbra.executor.claude")

# Tools that would let the agent push, merge, or otherwise self-grant authority.
# Refused at the CLI layer so a governed run can only ever propose a change.
_DISALLOWED_TOOLS = [
    # Push / publish / merge — an agent must never self-merge or publish.
    "Bash(git push:*)",
    "Bash(git commit:*)",
    "Bash(git merge:*)",
    "Bash(git rebase:*)",
    "Bash(git remote:*)",
    "Bash(gh pr:*)",
    "Bash(gh api:*)",
    "Bash(gh release:*)",
    "Bash(gh workflow:*)",
    "Bash(gh secret:*)",
    "Bash(gh auth:*)",
    # Network / exfiltration primitives.
    "Bash(curl:*)",
    "Bash(wget:*)",
    "Bash(nc:*)",
    "Bash(ncat:*)",
    "Bash(ssh:*)",
    "Bash(scp:*)",
    "Bash(rsync:*)",
    "WebFetch",
]


class ClaudeCodeExecutor:
    name = "claude-code"

    def __init__(
        self,
        runner: Runner = subprocess.run,
        model: str | None = None,
    ) -> None:
        self.runner = runner
        # Free-form alias/full name (e.g. "opus", "sonnet"); passed only via
        # --model. No allowlist coupling to a specific vendor catalog.
        self.model = (model if model is not None else os.getenv("UMBRA_CLAUDE_MODEL") or "").strip() or None

    # --- capability ---------------------------------------------------------
    def available(self) -> bool:
        if os.getenv("UMBRA_ENABLE_CLAUDE_CODE", "false").lower() != "true":
            return False
        return self._cli_version() is not None

    def _cli_version(self) -> str | None:
        try:
            r = self.runner(["claude", "--version"], text=True, capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if r is None:
            return None
        out = ((getattr(r, "stdout", "") or "") + (getattr(r, "stderr", "") or "")).strip()
        return out.splitlines()[0].strip() if out else None

    # --- provenance ---------------------------------------------------------
    def model_identity(self) -> dict[str, Any]:
        return {
            "executor": self.name,
            "cli_version": self._cli_version() or "unavailable",
            "model_configured": self.model or "claude-default",
            # Resolved only if the CLI's JSON result reports the model that ran;
            # filled in _run_cli when observed. Never inferred from --model.
            "model_resolved": "unavailable",
            "model_evidence": "cli-argument" if self.model else "claude-default",
        }

    # --- run ----------------------------------------------------------------
    def propose(self, prompt: str, repo_path: Path, *, read_only: bool = False) -> ExecutionResult:
        if not self.available():
            return ExecutionResult.disabled(
                prompt, self.name,
                "Claude Code is disabled. Set UMBRA_ENABLE_CLAUDE_CODE=true and authenticate the `claude` CLI.",
            )
        if repo_path is None or not repo_path.is_dir():
            raise RuntimeError("A checked-out repository is required for ClaudeCodeExecutor.propose()")
        return self._run_cli(prompt, repo_path, read_only=read_only)

    def _run_cli(self, prompt: str, repo_path: Path, *, read_only: bool) -> ExecutionResult:
        # acceptEdits lets the agent edit files in the checkout without prompting;
        # plan mode forbids edits entirely for a read-only reasoning pass.
        permission_mode = "plan" if read_only else "acceptEdits"
        model_args = ["--model", self.model] if self.model else []
        cli_prompt = reason_prompt(prompt, "Claude Code") if read_only else bounded_prompt(prompt, "Claude Code")
        command = [
            "claude", "-p", cli_prompt,
            "--output-format", "json",
            "--bare",  # do NOT auto-read CLAUDE.md — Umbra's trust boundary owns that
            "--permission-mode", permission_mode,
            "--disallowed-tools", *_DISALLOWED_TOOLS,
            "--add-dir", str(repo_path),
            *model_args,
        ]
        try:
            completed = self.runner(
                command, text=True, capture_output=True, timeout=900, check=False, cwd=str(repo_path),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return ExecutionResult.failed(prompt, self.name, str(exc)[:300], command=command[:2] + ["<prompt>"])

        rc = getattr(completed, "returncode", 1)
        raw_stdout = getattr(completed, "stdout", "") or ""
        summary, resolved_model = self._parse_result(raw_stdout)

        diff = unified_diff(repo_path)
        files = changed_files(repo_path)
        if not summary:
            summary = (
                ("Claude Code completed; see the diff below." if diff else "Claude Code ran and produced no changes.")
                if rc == 0
                else f"Claude Code failed (exit {rc})."
            )
        if rc != 0:
            logger.warning("claude -p failed (rc=%s): %s", rc, (getattr(completed, "stderr", "") or "")[-1000:])

        identity = self.model_identity()
        if resolved_model:
            identity["model_resolved"] = resolved_model
            identity["model_evidence"] = "provider-attested"

        return ExecutionResult(
            prompt=prompt,
            summary=sanitize_paths(summary, repo_path),
            diff=diff,
            tests_passed=rc == 0,
            files=files,
            executor=self.name if rc == 0 else "unavailable",
            created_at=datetime.now(UTC).isoformat(),
            command=command[:2] + ["<agent prompt redacted from command replay>"] + command[3:],
            stdout=sanitize_paths(raw_stdout[-12000:], repo_path),
            error=sanitize_paths((getattr(completed, "stderr", "") or "")[-4000:], repo_path) or None,
            model_identity=identity,
        )

    @staticmethod
    def _parse_result(stdout: str) -> tuple[str, str | None]:
        """Extract the final assistant text and (if reported) the resolved model
        from ``--output-format json``. Falls back to raw stdout on any parse
        failure — we never fabricate a model that ran.
        """
        text = (stdout or "").strip()
        if not text:
            return "", None
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return text, None
        summary = ""
        resolved = None
        if isinstance(data, dict):
            summary = str(data.get("result") or data.get("text") or data.get("content") or "").strip()
            model = data.get("model")
            if isinstance(model, str) and model.strip():
                resolved = model.strip()
        return summary or text, resolved
