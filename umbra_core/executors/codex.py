"""Codex CLI executor — adapts ``codex exec`` to the Executor protocol.

Ported from Umbra's original ``codex_client.py`` and reshaped to the
agent-agnostic :class:`~umbra_core.executors.base.Executor` interface. Codex is
run against a disposable checkout with a hard no-push/no-merge instruction and
no GitHub write credentials.
"""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
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

logger = logging.getLogger("umbra.executor.codex")

# Only these values are ever passed to codex exec's -m / -c flags, so an
# arbitrary caller can never inject config. luna=fastest, terra=balanced, sol=deepest.
_CODEX_MODELS = {"gpt-5.6-luna", "gpt-5.6-terra", "gpt-5.6-sol"}
_CODEX_EFFORTS = {"minimal", "low", "medium", "high"}


class CodexExecutor:
    name = "codex-cli"

    def __init__(
        self,
        runner: Runner = subprocess.run,
        model: str | None = None,
        reasoning_effort: str | None = None,
    ) -> None:
        self.runner = runner
        self.model = self._resolve_model(model if model is not None else os.getenv("UMBRA_CODEX_MODEL"))
        self.reasoning_effort = self._resolve_effort(
            reasoning_effort if reasoning_effort is not None else os.getenv("UMBRA_CODEX_REASONING_EFFORT")
        )

    # --- capability ---------------------------------------------------------
    def available(self) -> bool:
        if os.getenv("UMBRA_ENABLE_CODEX_CLI", "false").lower() != "true":
            return False
        return self._cli_version() is not None

    def _cli_version(self) -> str | None:
        try:
            r = self.runner(["codex", "--version"], text=True, capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if r is None:
            return None
        out = ((getattr(r, "stdout", "") or "") + (getattr(r, "stderr", "") or "")).strip()
        return out.splitlines()[0].strip() if out else None

    # --- provenance ---------------------------------------------------------
    def model_identity(self) -> dict[str, Any]:
        pinned = self.model
        return {
            "executor": self.name,
            "cli_version": self._cli_version() or "unavailable",
            "model_configured": pinned or "codex-default",
            # A -m model is REQUESTED, not attested-as-run; stays unavailable
            # unless the CLI explicitly reports the resolved model.
            "model_resolved": "unavailable",
            "model_evidence": "cli-argument" if pinned else "codex-default",
            "reasoning_effort": self.reasoning_effort or "codex-default",
        }

    @staticmethod
    def _resolve_model(value: str | None) -> str | None:
        value = (value or "").strip()
        return value if value in _CODEX_MODELS else None

    @staticmethod
    def _resolve_effort(value: str | None) -> str | None:
        value = (value or "").strip().lower()
        return value if value in _CODEX_EFFORTS else None

    # --- run ----------------------------------------------------------------
    def propose(self, prompt: str, repo_path: Path, *, read_only: bool = False) -> ExecutionResult:
        if not self.available():
            return ExecutionResult.disabled(
                prompt, self.name,
                "Codex CLI is disabled. Set UMBRA_ENABLE_CODEX_CLI=true and authenticate with `codex login`.",
            )
        if repo_path is None or not repo_path.is_dir():
            raise RuntimeError("A checked-out repository is required for CodexExecutor.propose()")
        return self._run_cli(prompt, repo_path, read_only=read_only)

    def _sandbox(self, read_only: bool) -> str:
        return "read-only" if read_only else "workspace-write"

    def _run_cli(self, prompt: str, repo_path: Path, *, read_only: bool) -> ExecutionResult:
        with tempfile.TemporaryDirectory(prefix="umbra-codex-") as temp_dir:
            final_message = Path(temp_dir) / "final-message.txt"
            sandbox = self._sandbox(read_only)
            model_args = ["-m", self.model] if self.model else []
            effort_args = ["-c", f'model_reasoning_effort="{self.reasoning_effort}"'] if self.reasoning_effort else []
            cli_prompt = reason_prompt(prompt, "Codex") if read_only else bounded_prompt(prompt, "Codex")
            command = [
                "codex", "exec", "--ephemeral", "--color", "never",
                "--sandbox", sandbox,
                *model_args, *effort_args,
                "--skip-git-repo-check",
                "--output-last-message", str(final_message),
                "-C", str(repo_path),
                cli_prompt,
            ]
            completed = self.runner(command, text=True, capture_output=True, timeout=900, check=False)
            diff = unified_diff(repo_path)
            files = changed_files(repo_path)
            final = final_message.read_text(errors="replace") if final_message.exists() else completed.stdout
            summary = (final or "").strip() or (completed.stdout or "").strip()
            rc = getattr(completed, "returncode", 1)
            if not summary:
                summary = (
                    ("Codex completed; see the diff below." if diff else "Codex ran and produced no changes.")
                    if rc == 0
                    else f"Codex CLI failed (exit {rc}, sandbox={sandbox})."
                )
            if rc != 0:
                logger.warning("codex exec failed (rc=%s): %s", rc, (getattr(completed, "stderr", "") or "")[-1000:])
            return ExecutionResult(
                prompt=prompt,
                summary=sanitize_paths(summary, repo_path),
                diff=diff,
                tests_passed=rc == 0,
                files=files,
                executor=self.name if rc == 0 else "unavailable",
                created_at=datetime.now(UTC).isoformat(),
                command=command[:-1] + ["<agent prompt redacted from command replay>"],
                stdout=sanitize_paths((getattr(completed, "stdout", "") or "")[-12000:], repo_path),
                error=sanitize_paths((getattr(completed, "stderr", "") or "")[-4000:], repo_path) or None,
                model_identity=self.model_identity(),
            )
