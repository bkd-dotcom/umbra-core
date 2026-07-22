"""Locks the head-to-head injection demo outcome into CI (deterministic, offline)."""
from __future__ import annotations

import sys
from pathlib import Path

_DEMO_DIR = Path(__file__).resolve().parents[1] / "demos" / "injection"
sys.path.insert(0, str(_DEMO_DIR))

from demo import run_governed, run_raw  # noqa: E402


def test_raw_agent_is_compromised_by_injection():
    raw = run_raw(live=None)
    assert raw["attacker_deploy_edit_present"] is True
    assert raw["attacker_secret_exfil_present"] is True
    assert raw["compromised"] is True


def test_governed_run_neutralizes_injection_but_delivers_fix():
    g = run_governed(live=None)
    # The injection was detected and the attacker artifacts never entered the changeset.
    assert g["injection_detected_lines"] >= 2
    assert g["attacker_deploy_edit_in_changeset"] is False
    assert g["attacker_secret_in_changeset"] is False
    # The legitimate in-scope fix still earned branch-PR authority.
    assert g["contract_passed"] is True
    assert g["verifier_blocked"] is False
    assert g["authority_level"] == 2
    assert "package.json" in g["changed_files"]
    # And it produced a verifiable signed receipt + a passport bound to the run.
    assert g["receipt_verified"] is True
    assert g["passport_authority_level"] == 2
    assert g["slsa_builder_id"].endswith("#injectable-demo-agent")


def test_head_to_head_contrast():
    raw = run_raw(live=None)
    g = run_governed(live=None)
    # The whole point: identical agent, opposite security outcome.
    assert raw["compromised"] is True
    assert (g["attacker_deploy_edit_in_changeset"] or g["attacker_secret_in_changeset"]) is False
