"""Executor registry — resolve any governed coding agent by name.

The registry is the single seam the pipeline uses to obtain an agent. It keeps
the governance core agent-agnostic: to add Cursor, Aider, or any future agent,
register one adapter here — no pipeline change required.
"""
from __future__ import annotations

import subprocess
from typing import Callable

from .base import Executor
from .claude_code import ClaudeCodeExecutor
from .codex import CodexExecutor
from .null import NullExecutor

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

# name -> factory(runner) -> Executor
_REGISTRY: dict[str, Callable[[Runner], Executor]] = {
    "codex-cli": lambda runner: CodexExecutor(runner=runner),
    "claude-code": lambda runner: ClaudeCodeExecutor(runner=runner),
    "none": lambda runner: NullExecutor(),  # govern an existing working-tree change
}


def available_executors() -> list[str]:
    return sorted(_REGISTRY)


def get_executor(name: str, runner: Runner = subprocess.run) -> Executor:
    try:
        return _REGISTRY[name](runner)
    except KeyError:
        raise ValueError(
            f"Unknown executor {name!r}. Registered: {', '.join(available_executors())}"
        ) from None


def resolve_available(preferred: list[str] | None = None, runner: Runner = subprocess.run) -> Executor | None:
    """Return the first *available* real coding agent, honoring an optional
    preference order. Returns None when no agent can run here (caller falls back
    or caps authority). The ``none`` (NullExecutor) is never auto-selected — it
    must be requested explicitly, since it produces no change.
    """
    order = preferred or [n for n in available_executors() if n != "none"]
    for name in order:
        if name not in _REGISTRY or name == "none":
            continue
        executor = _REGISTRY[name](runner)
        if executor.available():
            return executor
    return None
