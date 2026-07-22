"""The agent-agnostic executor interface.

The central idea of umbra-core: a coding agent (Codex, Claude Code, Cursor, …)
is an *untrusted engine*. It proposes a change inside a disposable checkout; it
never pushes, commits, or merges, and it can never approve its own authority.

Every agent is adapted to one interface — :class:`Executor` — so the admission
pipeline (contract → trust boundary → checks → verifier → earned authority →
signed receipt) treats them identically. Adding a new agent means writing one
adapter, not touching the governance core.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@dataclass
class ExecutionResult:
    """The auditable, replayable record of a single agent invocation.

    Fields are deliberately provider-neutral so a receipt can bind any agent's
    output identically. Honesty rule: ``provider`` describes *produced* output,
    never a mere launch attempt — a failed run is recorded as such, never green.
    """

    prompt: str
    summary: str
    diff: str
    tests_passed: bool | None
    files: list[str]
    # Which agent produced this — e.g. "codex-cli", "claude-code", "cursor",
    # "deterministic". Never fabricated; a failed run reports "unavailable".
    executor: str
    created_at: str
    command: list[str] | None = None
    stdout: str = ""
    error: str | None = None
    # Provider-attested model provenance for the signed receipt. Kept honest:
    # "configured" is what we requested, "resolved" stays unavailable unless the
    # agent explicitly reports the model that ran.
    model_identity: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def failed(cls, prompt: str, executor: str, error: str, command: list[str] | None = None) -> "ExecutionResult":
        return cls(
            prompt=prompt,
            summary=f"{executor} did not produce a change: {error}",
            diff="",
            tests_passed=False,
            files=[],
            executor="unavailable",
            created_at=datetime.now(UTC).isoformat(),
            command=command,
            error=error,
        )

    @classmethod
    def disabled(cls, prompt: str, executor: str, reason: str) -> "ExecutionResult":
        return cls(
            prompt=prompt,
            summary=reason,
            diff="",
            tests_passed=None,
            files=[],
            executor=f"{executor}-disabled",
            created_at=datetime.now(UTC).isoformat(),
        )


@runtime_checkable
class Executor(Protocol):
    """Any coding agent Umbra can govern.

    Implementations wrap a CLI or API (Codex, Claude Code, Cursor, …) behind
    this single contract. The governance core depends only on this protocol, so
    it is fully agent-agnostic.
    """

    #: Stable identifier used in receipts and the provider ledger.
    name: str

    def available(self) -> bool:
        """Whether this agent can actually run here (binary present, auth ok).

        Must never raise; a probe failure returns ``False`` so the pipeline can
        fall back or cap authority rather than crash.
        """
        ...

    def propose(self, prompt: str, repo_path: Path, *, read_only: bool = False) -> ExecutionResult:
        """Run the agent in ``repo_path`` (a disposable checkout) and return the
        produced change as an :class:`ExecutionResult`.

        The agent MUST be invoked with no push/commit/merge authority and no
        write credentials. ``read_only`` requests a pure-reasoning pass with no
        filesystem side effects.
        """
        ...

    def model_identity(self) -> dict[str, Any]:
        """Truthful model provenance for the receipt (never fabricated)."""
        ...
