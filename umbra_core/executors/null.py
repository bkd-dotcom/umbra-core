"""NullExecutor — govern a change that already exists in the working tree.

Not every governed run *produces* a change. In CI, the coding agent already ran
and opened a PR; the change is the diff between the base and the PR head. The
NullExecutor makes no edits — it lets the admission pipeline evaluate whatever is
already present in the checkout against the contract, checks, and verifier.

This is how umbra-core governs *any* agent's PR without re-running the agent: the
agent's work is already on disk, and the pipeline judges it on the evidence.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import ExecutionResult


class NullExecutor:
    """Reviews the existing working tree; produces no change of its own."""

    name = "none"

    def available(self) -> bool:
        return True

    def propose(self, prompt: str, repo_path: Path, *, read_only: bool = False) -> ExecutionResult:  # noqa: ARG002
        return ExecutionResult(
            prompt=prompt,
            summary="No agent invoked — evaluating the change already present in the working tree.",
            diff="",
            tests_passed=None,
            files=[],
            executor=self.name,
            created_at="now",
            model_identity=self.model_identity(),
        )

    def model_identity(self) -> dict[str, Any]:
        return {
            "executor": self.name,
            "model_configured": None,
            "model_resolved": None,
            "model_evidence": "no-model",
            "note": "No coding model was invoked; the existing working-tree change was governed as-is.",
        }
