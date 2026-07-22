"""Tests for the accountability layer: earned-authority passport + Emergency Brake,
SLSA/in-toto provenance, and the append-only Merkle transparency log."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from umbra_core import (
    InMemoryLogStore,
    InMemoryPassportStore,
    PassportError,
    TransparencyLog,
    build_receipt,
    evaluate_passport,
    gate_pr,
    issue_passport,
    merkle_root,
    revoke,
    to_slsa_provenance,
    verify_inclusion,
)
from umbra_core.pipeline.provenance import SLSA_PREDICATE_TYPE, STATEMENT_TYPE


def _report_dict(level=2, authority="branch_pr"):
    return {
        "repo": "acme/app",
        "task_type": "dependency-remediation",
        "executor": "claude-code",
        "authority_level": level,
        "authority": authority,
        "authority_label": "Prepare branch-only PR",
        "outcome": "ADMITTED (branch PR)",
        "base_commit": "abc123",
        "diff_hash": "sha256:" + "d" * 64,
        "contract_result": {"contract_hash": "sha256:" + "c" * 64, "passed": True},
        "verifier": {"status": "reviewable", "blocked": False},
        "checks": {"enforcement": "sandboxed", "all_passed": True},
        "trust_boundary": {"clean": True, "quarantined_count": 0},
        "model_identity": {"model_configured": "opus", "model_resolved": "unavailable"},
    }


def _envelope(level=2, authority="branch_pr"):
    r = _report_dict(level, authority)
    return build_receipt(
        repo=r["repo"], base_commit=r["base_commit"], contract={}, contract_result=r["contract_result"],
        verifier=r["verifier"], trust_boundary=r["trust_boundary"], proposed_change=None,
        providers={}, authority_level=r["authority_level"], authority=r["authority"],
        executor=r["executor"], diff=None, diff_hash=r["diff_hash"], checks=r["checks"],
        model_identity=r["model_identity"], outcome=r["outcome"],
    )


# --- passport ---------------------------------------------------------------

def test_issue_passport_binds_run_and_never_auto_merges():
    p = issue_passport(_report_dict(level=2))
    assert p["authority_level"] == 2
    assert p["executor"] == "claude-code"
    assert p["base_commit"] == "abc123"
    assert p["auto_merge"] is False
    assert p["revoked"] is False
    assert p["expires_at"] > p["admitted_at"]


def test_l2_passport_permits_pr():
    store = InMemoryPassportStore()
    store.save("owner1", "acme/app", issue_passport(_report_dict(level=2)))
    status = evaluate_passport(store, "owner1", "acme/app")
    assert status.ok is True
    assert gate_pr(store, "owner1", "acme/app")["authority_level"] == 2


def test_below_l2_passport_blocks_pr():
    store = InMemoryPassportStore()
    store.save("owner1", "acme/app", issue_passport(_report_dict(level=1, authority="analyze")))
    with pytest.raises(PassportError):
        gate_pr(store, "owner1", "acme/app")


def test_emergency_brake_revokes_and_blocks():
    store = InMemoryPassportStore()
    store.save("owner1", "acme/app", issue_passport(_report_dict(level=2)))
    assert gate_pr(store, "owner1", "acme/app")  # allowed before

    revoked = revoke(store, "owner1", "acme/app", reason="incident-42")
    assert revoked["revoked"] is True
    assert revoked["authority_level"] == 0
    with pytest.raises(PassportError, match="revoked"):
        gate_pr(store, "owner1", "acme/app")


def test_brake_on_unknown_repo_creates_revoked_record():
    store = InMemoryPassportStore()
    revoke(store, "owner1", "never/admitted")
    with pytest.raises(PassportError):
        gate_pr(store, "owner1", "never/admitted")


def test_no_passport_allows_when_not_strict_and_blocks_in_strict():
    store = InMemoryPassportStore()
    assert evaluate_passport(store, "owner1", "acme/app").ok is True
    assert evaluate_passport(store, "owner1", "acme/app", require_admission=True).ok is False
    with pytest.raises(PassportError):
        gate_pr(store, "owner1", "acme/app", require_admission=True)


def test_expired_passport_blocks_pr():
    store = InMemoryPassportStore()
    p = issue_passport(_report_dict(level=2))
    p["expires_at"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    store.save("owner1", "acme/app", p)
    with pytest.raises(PassportError, match="expired"):
        gate_pr(store, "owner1", "acme/app")


def test_passport_isolation_between_owners():
    store = InMemoryPassportStore()
    store.save("owner1", "acme/app", issue_passport(_report_dict(level=2)))
    # owner2 has no passport for the same repo.
    assert store.get("owner2", "acme/app") is None
    assert len(store.list("owner1")) == 1
    assert store.list("owner2") == []


# --- SLSA / in-toto provenance ----------------------------------------------

def test_slsa_provenance_shape_and_builder_encodes_agent():
    env = _envelope(level=2)
    stmt = to_slsa_provenance(env)
    assert stmt["_type"] == STATEMENT_TYPE
    assert stmt["predicateType"] == SLSA_PREDICATE_TYPE
    # subject digest is the diff hash (hex, no sha256: prefix)
    assert stmt["subject"][0]["digest"]["sha256"] == "d" * 64
    # builder id encodes the executor so a verifier sees which agent produced it
    assert stmt["predicate"]["runDetails"]["builder"]["id"].endswith("#claude-code")
    # umbra evidence extension carries earned authority + invariants
    umbra = stmt["predicate"]["umbra"]
    assert umbra["authority_level"] == 2
    assert umbra["auto_merge"] is False
    assert umbra["human_review_required"] is True
    assert umbra["signature"] == env["signature"]


def test_slsa_byproduct_binds_receipt_hash():
    env = _envelope()
    stmt = to_slsa_provenance(env)
    byproduct = stmt["predicate"]["runDetails"]["byproducts"][0]
    assert byproduct["digest"]["sha256"] == env["canonical_hash"][len("sha256:"):]


# --- transparency log -------------------------------------------------------

def test_append_and_inclusion_proof_verifies():
    log = TransparencyLog(InMemoryLogStore())
    a = log.append_receipt(_envelope(level=2))
    b = log.append_receipt(_envelope(level=1, authority="analyze"))
    assert a["size"] == 1
    assert b["size"] == 2
    # inclusion proof for entry 0 recomputes to the CURRENT root
    proof0 = log.prove_inclusion(0)
    assert verify_inclusion(proof0["leaf"], 0, proof0["proof"], proof0["root"]) is True
    proof1 = log.prove_inclusion(1)
    assert verify_inclusion(proof1["leaf"], 1, proof1["proof"], proof1["root"]) is True


def test_inclusion_proof_fails_against_wrong_root():
    log = TransparencyLog()
    log.append_receipt(_envelope())
    log.append_receipt(_envelope())
    p = log.prove_inclusion(0)
    assert verify_inclusion(p["leaf"], 0, p["proof"], "deadbeef" * 8) is False


def test_append_only_consistency_detects_rewrite():
    store = InMemoryLogStore()
    log = TransparencyLog(store)
    log.append_receipt(_envelope())
    log.append_receipt(_envelope())
    old_root, old_size = log.root(), log.size()

    # Legitimate growth preserves the historical prefix.
    log.append_receipt(_envelope())
    assert log.verify_appended_since(old_root, old_size) is True

    # Tamper: rewrite an old entry's leaf in place -> prefix root changes -> fail.
    entries = store.all()
    entries[0]["leaf"] = "00" * 32
    store._entries = entries  # type: ignore[attr-defined]
    assert log.verify_appended_since(old_root, old_size) is False


def test_merkle_root_is_deterministic_and_order_sensitive():
    leaves = ["aa" * 32, "bb" * 32, "cc" * 32]
    assert merkle_root(leaves) == merkle_root(leaves)
    assert merkle_root(leaves) != merkle_root(list(reversed(leaves)))


def test_empty_log_has_stable_root():
    log = TransparencyLog()
    assert log.size() == 0
    assert isinstance(log.root(), str) and len(log.root()) == 64
