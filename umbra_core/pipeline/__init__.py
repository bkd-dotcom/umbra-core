"""The governed admission pipeline: contract -> trust boundary -> checks ->
verifier -> earned authority -> signed receipt. Agent-agnostic — driven by any
:class:`~umbra_core.executors.base.Executor`."""
from .admission import (
    AUTHORITY,
    AUTHORITY_LABEL,
    AdmissionReport,
    run_admission,
)
from .checks import ChecksReport, CheckResult, run_required_checks
from .contract import (
    Contract,
    ContractResult,
    default_contract,
    evaluate_contract,
    load_contract,
)
from .receipt import (
    build_receipt,
    public_key_b64,
    sign,
    signing_key_is_ephemeral,
    verify_receipt,
    verify_signature,
)
from .trust_boundary import (
    TrustBoundaryResult,
    sanitize_checkout,
    scan_repository_text,
    scan_text,
)
from .verifier import VerifierReport, verify_change

__all__ = [
    "AdmissionReport",
    "run_admission",
    "AUTHORITY",
    "AUTHORITY_LABEL",
    "Contract",
    "ContractResult",
    "default_contract",
    "evaluate_contract",
    "load_contract",
    "ChecksReport",
    "CheckResult",
    "run_required_checks",
    "TrustBoundaryResult",
    "scan_repository_text",
    "scan_text",
    "sanitize_checkout",
    "VerifierReport",
    "verify_change",
    "build_receipt",
    "verify_receipt",
    "verify_signature",
    "sign",
    "public_key_b64",
    "signing_key_is_ephemeral",
]
