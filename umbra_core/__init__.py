"""umbra-core — an agent-agnostic change-control plane for coding agents."""
from .executors.base import ExecutionResult, Executor
from .executors.claude_code import ClaudeCodeExecutor
from .executors.codex import CodexExecutor
from .executors.registry import (
    available_executors,
    get_executor,
    resolve_available,
)

__version__ = "0.1.0"

__all__ = [
    "Executor",
    "ExecutionResult",
    "CodexExecutor",
    "ClaudeCodeExecutor",
    "available_executors",
    "get_executor",
    "resolve_available",
    "__version__",
]
