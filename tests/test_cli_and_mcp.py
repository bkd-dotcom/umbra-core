"""Tests for the CLI and MCP tool functions (hermetic, offline)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


from umbra_core.cli import main as cli_main
from umbra_core.executors.base import ExecutionResult
from umbra_core.mcp_server import _provenance, _verify

_DEMO_DIR = Path(__file__).resolve().parents[1] / "demos" / "injection"
sys.path.insert(0, str(_DEMO_DIR))
from demo import InjectableAgent, MISSION, _fresh_checkout  # noqa: E402

from umbra_core import build_receipt, run_admission  # noqa: E402


def _make_receipt(tmp_path: Path) -> Path:
    work = _fresh_checkout()
    try:
        r = run_admission(work, "acme/app", MISSION, InjectableAgent(),
                          proposed_change={"package": "left-pad", "fixed": "1.3.0"})
        env = build_receipt(
            repo=r.repo, base_commit=r.base_commit, contract=r.contract,
            contract_result=r.contract_result, verifier=r.verifier,
            trust_boundary=r.trust_boundary, proposed_change=r.proposed_change,
            providers=r.providers, authority_level=r.authority_level,
            authority=r.authority, executor=r.executor, diff=r.diff,
            checks=r.checks, model_identity=r.model_identity, outcome=r.outcome,
        )
    finally:
        import shutil
        shutil.rmtree(work.parent, ignore_errors=True)
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(env, default=str))
    return path


# --- CLI: verify / provenance / brake (no live agent needed) ----------------

def test_cli_verify_ok(tmp_path, capsys):
    from umbra_core import public_key_b64
    receipt = _make_receipt(tmp_path)
    rc = cli_main(["verify", str(receipt), "--public-key", public_key_b64()])
    assert rc == 0
    assert "VERIFIED" in capsys.readouterr().out


def test_cli_verify_refuses_dev_key_without_pin(tmp_path, capsys):
    # SECURITY: without --public-key and on the dev key, verify must refuse.
    receipt = _make_receipt(tmp_path)
    rc = cli_main(["verify", str(receipt)])
    assert rc == 1
    assert "NOT VERIFIED" in capsys.readouterr().out


def test_cli_verify_tampered_fails(tmp_path, capsys):
    from umbra_core import public_key_b64
    receipt = _make_receipt(tmp_path)
    env = json.loads(receipt.read_text())
    env["receipt"]["authority_level"] = 99  # tamper
    receipt.write_text(json.dumps(env))
    rc = cli_main(["verify", str(receipt), "--public-key", public_key_b64()])
    assert rc == 1
    assert "NOT VERIFIED" in capsys.readouterr().out


def test_cli_provenance_emits_intoto(tmp_path, capsys):
    receipt = _make_receipt(tmp_path)
    rc = cli_main(["provenance", str(receipt)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["_type"].startswith("https://in-toto.io/Statement")


def test_cli_brake_writes_store(tmp_path):
    store = tmp_path / "passports.json"
    rc = cli_main(["brake", "acme", "app", "--store", str(store), "--reason", "incident"])
    assert rc == 0
    data = json.loads(store.read_text())
    rec = next(iter(data.values()))
    assert rec["revoked"] is True
    assert rec["authority_level"] == 0


def test_cli_admit_no_agent_returns_error(tmp_path, monkeypatch):
    monkeypatch.delenv("UMBRA_ENABLE_CODEX_CLI", raising=False)
    monkeypatch.delenv("UMBRA_ENABLE_CLAUDE_CODE", raising=False)
    (tmp_path / ".git").mkdir()  # looks like a repo dir
    rc = cli_main(["admit", str(tmp_path), "--mission", "x"])
    assert rc == 2  # no agent available


# --- CLI admit with an installed fake agent via the entry point -------------

def test_cli_admit_end_to_end_via_registry(tmp_path, monkeypatch, capsys):
    # Register a fake agent into the registry so `admit --agent` works offline.
    import umbra_core.executors.registry as reg

    class OKAgent:
        name = "fake-cli-agent"
        def available(self): return True
        def propose(self, prompt, repo_path, *, read_only=False):
            (repo_path / "package.json").write_text('{"dependencies":{"left-pad":"1.3.0"}}\n')
            return ExecutionResult(prompt=prompt, summary="ok", diff="", tests_passed=True,
                                   files=["package.json"], executor=self.name, created_at="now",
                                   model_identity=self.model_identity())
        def model_identity(self) -> dict[str, Any]:
            return {"executor": self.name}

    monkeypatch.setitem(reg._REGISTRY, "fake-cli-agent", lambda runner: OKAgent())
    monkeypatch.setattr(
        "umbra_core.cli.get_executor",
        lambda name, *a, **k: OKAgent() if name == "fake-cli-agent" else reg.get_executor(name),
    )

    # Build a minimal governed repo.
    (tmp_path / ".umbra").mkdir()
    (tmp_path / ".umbra" / "admission.yaml").write_text(
        'version: 1\nallowed_paths:\n  - package.json\nrequired_checks:\n  - "true"\n'
    )
    (tmp_path / "package.json").write_text('{"dependencies":{"left-pad":"1.0.0"}}\n')
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t.co"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "b"], cwd=tmp_path, check=True)

    receipt_out = tmp_path / "r.json"
    rc = cli_main([
        "admit", str(tmp_path), "--mission", "bump left-pad",
        "--agent", "fake-cli-agent", "--receipt-out", str(receipt_out),
        "--min-authority", "2",
    ])
    assert rc == 0  # earned L2
    assert receipt_out.is_file()
    assert "authority   : L2" in capsys.readouterr().out


# --- MCP tool functions -----------------------------------------------------

def test_mcp_verify_and_provenance(tmp_path):
    from umbra_core import public_key_b64
    receipt = _make_receipt(tmp_path)
    env_text = receipt.read_text()
    assert _verify(env_text, public_key_b64())["verified"] is True
    # Without an explicit key, a dev-key receipt is refused.
    assert _verify(env_text)["verified"] is False
    stmt = _provenance(env_text)
    assert stmt["predicateType"].startswith("https://slsa.dev/provenance")


def test_mcp_verify_bad_json():
    assert "error" in _verify("{not json")
