"""umbra-core — an agent-agnostic change-control plane for coding agents."""
from .executors.base import ExecutionResult, Executor
from .executors.claude_code import ClaudeCodeExecutor
from .executors.codex import CodexExecutor
from .executors.registry import (
    available_executors,
    get_executor,
    resolve_available,
)
from .pipeline import (
    AUTHORITY,
    AUTHORITY_LABEL,
    AdmissionReport,
    ChecksReport,
    Contract,
    ContractResult,
    TrustBoundaryResult,
    VerifierReport,
    build_receipt,
    default_contract,
    evaluate_contract,
    load_contract,
    public_key_b64,
    run_admission,
    run_required_checks,
    sanitize_checkout,
    scan_repository_text,
    sign,
    verify_change,
    verify_receipt,
    verify_signature,
)

__version__ = "0.1.0"

__all__ = [
    # executors
    "Executor",
    "ExecutionResult",
    "CodexExecutor",
    "ClaudeCodeExecutor",
    "available_executors",
    "get_executor",
    "resolve_available",
    # pipeline
    "run_admission",
    "AdmissionReport",
    "AUTHORITY",
    "AUTHORITY_LABEL",
    "Contract",
    "ContractResult",
    "default_contract",
    "evaluate_contract",
    "load_contract",
    "ChecksReport",
    "run_required_checks",
    "TrustBoundaryResult",
    "scan_repository_text",
    "sanitize_checkout",
    "VerifierReport",
    "verify_change",
    "build_receipt",
    "verify_receipt",
    "verify_signature",
    "sign",
    "public_key_b64",
    "__version__",
]
