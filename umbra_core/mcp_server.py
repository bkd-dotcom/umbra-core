"""MCP server exposing umbra-core's governance as tools.

Agents that speak the Model Context Protocol (Claude Code, Cursor, …) can call
these tools to run their own change through the admission pipeline *before*
proposing it, and to verify receipts. The agent still cannot approve itself — the
tools run the deterministic pipeline and return the earned authority + a signed
receipt; the verdict is produced outside the model.

Run it:
    pip install "umbra-core[mcp]"
    python -m umbra_core.mcp_server        # stdio transport

Register it with an MCP client (e.g. Claude Code) pointing at this command.

Tools:
    umbra_admit(repo_path, mission, agent?) -> {report, receipt}
    umbra_verify(receipt_json)              -> verification result
    umbra_provenance(receipt_json)          -> in-toto/SLSA statement
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import (
    build_receipt,
    get_executor,
    resolve_available,
    run_admission,
    to_slsa_provenance,
    verify_receipt,
)


def _admit(repo_path: str, mission: str, agent: str | None = None, label: str | None = None) -> dict[str, Any]:
    root = Path(repo_path).resolve()
    if not root.is_dir():
        return {"error": f"{root} is not a directory"}
    if agent:
        executor = get_executor(agent)
        if not executor.available():
            return {"error": f"agent {agent!r} is not available (enable + authenticate it)"}
    else:
        executor = resolve_available()
        if executor is None:
            return {"error": "no coding agent available; set UMBRA_ENABLE_CLAUDE_CODE=true or UMBRA_ENABLE_CODEX_CLI=true, or pass agent"}
    report = run_admission(root, label or root.name, mission, executor)
    envelope = build_receipt(
        repo=report.repo, base_commit=report.base_commit, contract=report.contract,
        contract_result=report.contract_result, verifier=report.verifier,
        trust_boundary=report.trust_boundary, proposed_change=report.proposed_change,
        providers=report.providers, authority_level=report.authority_level,
        authority=report.authority, executor=report.executor, diff=report.diff,
        checks=report.checks, model_identity=report.model_identity, outcome=report.outcome,
    )
    return {"report": report.to_public(), "receipt": envelope}


def _verify(receipt_json: str, public_key: str | None = None) -> dict[str, Any]:
    try:
        envelope = json.loads(receipt_json)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"error": f"invalid receipt JSON: {exc}"}
    return verify_receipt(envelope, expected_public_key=public_key)


def _provenance(receipt_json: str) -> dict[str, Any]:
    try:
        envelope = json.loads(receipt_json)
    except (json.JSONDecodeError, ValueError) as exc:
        return {"error": f"invalid receipt JSON: {exc}"}
    return to_slsa_provenance(envelope)


def build_server():  # pragma: no cover - exercised only when mcp is installed
    """Construct the FastMCP server. Requires the optional ``mcp`` dependency."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # noqa: F841
        raise SystemExit(
            "The MCP server needs the optional dependency: pip install 'umbra-core[mcp]'"
        ) from None

    mcp = FastMCP("umbra-core")

    @mcp.tool()
    def umbra_admit(repo_path: str, mission: str, agent: str | None = None, label: str | None = None) -> dict[str, Any]:
        """Run the Umbra admission pipeline on a checkout: govern an agent's change
        (contract, trust boundary, checks, independent verifier) and return the
        earned authority (0/1/2) plus a signed receipt. auto_merge is always false."""
        return _admit(repo_path, mission, agent, label)

    @mcp.tool()
    def umbra_verify(receipt_json: str, public_key: str | None = None) -> dict[str, Any]:
        """Verify a signed Umbra receipt against a pinned public key. Pass the
        production public_key; without it, verification of a dev-key receipt is
        refused (the dev seed is public)."""
        return _verify(receipt_json, public_key)

    @mcp.tool()
    def umbra_provenance(receipt_json: str) -> dict[str, Any]:
        """Convert a signed receipt into an in-toto Statement + SLSA Provenance v1
        predicate for supply-chain tooling."""
        return _provenance(receipt_json)

    return mcp


def main() -> None:  # pragma: no cover
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
