"""SLSA / in-toto provenance for admission receipts.

An Umbra Remediation Receipt is proof of *how much authority a change earned and
why*. This module expresses that same evidence in the **in-toto Statement** shape
carrying a **SLSA Provenance v1 predicate**, so a receipt plugs into existing
supply-chain tooling (Sigstore, `slsa-verifier`, GitHub attestations) instead of
being an Umbra-only artifact.

Mapping (honest, lossless where the vocabularies align):
- ``subject``            — the change: the diff hash as a digest, named by repo/commit.
- ``predicate.builder``  — the governed pipeline + the executor that ran (Codex /
                           Claude Code / …). The builder id encodes the agent, so a
                           verifier sees which agent produced the artifact.
- ``runDetails``         — the admission verdict: earned authority, contract hash,
                           verifier status, checks enforcement — the evidence.
- ``buildDefinition``    — the mission + contract + trust-boundary as the "recipe".

This is a *representation*; the Ed25519 signature over the canonical receipt
remains the tamper-evidence. Where SLSA has no field for a concept (earned
authority, quarantine count), it is carried under an ``umbra`` extension key
namespaced to avoid colliding with the standard predicate.
"""
from __future__ import annotations

from typing import Any

# Predicate type URIs (SLSA Provenance v1 / in-toto Statement v1).
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
UMBRA_BUILD_TYPE = "https://umbra.engineer/admission/v1"


def _digest_from_hash(sha_hash: str | None) -> dict[str, str]:
    """Turn an ``sha256:...`` hash into an in-toto digest map ``{"sha256": "<hex>"}``."""
    if not sha_hash:
        return {}
    if sha_hash.startswith("sha256:"):
        return {"sha256": sha_hash[len("sha256:"):]}
    return {"sha256": sha_hash}


def to_slsa_provenance(envelope: dict[str, Any]) -> dict[str, Any]:
    """Convert a signed receipt envelope into an in-toto Statement + SLSA predicate.

    ``envelope`` is the dict returned by
    :func:`umbra_core.pipeline.receipt.build_receipt`.
    """
    receipt = envelope.get("receipt") or {}
    repo = receipt.get("repo") or "unknown"
    base_commit = receipt.get("base_commit")
    executor = receipt.get("executor") or "unknown"
    contract_result = receipt.get("contract_result") or {}
    verifier = receipt.get("verifier") or {}
    checks = receipt.get("checks") or {}
    model_identity = receipt.get("model_identity") or {}
    trust_boundary = receipt.get("trust_boundary") or {}

    subject_name = f"{repo}@{base_commit}" if base_commit else repo
    subject_digest = _digest_from_hash(receipt.get("diff_hash"))

    statement: dict[str, Any] = {
        "_type": STATEMENT_TYPE,
        "predicateType": SLSA_PREDICATE_TYPE,
        "subject": [
            {
                "name": subject_name,
                # The diff hash is the artifact's content identity here.
                "digest": subject_digest or {"sha256": "0" * 64},
            }
        ],
        "predicate": {
            "buildDefinition": {
                "buildType": UMBRA_BUILD_TYPE,
                "externalParameters": {
                    "repository": repo,
                    "mission_task_type": receipt.get("task_type"),
                    "contract_hash": receipt.get("policy_hash") or contract_result.get("contract_hash"),
                },
                "internalParameters": {
                    "executor": executor,
                    "model_configured": model_identity.get("model_configured"),
                    "model_resolved": model_identity.get("model_resolved"),
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+repo://{repo}",
                        "digest": _digest_from_hash(f"sha256:{base_commit}") if base_commit else {},
                    }
                ],
            },
            "runDetails": {
                "builder": {
                    # The builder identity encodes the governing pipeline AND the
                    # agent that ran, so a verifier sees who produced the artifact.
                    "id": f"{UMBRA_BUILD_TYPE}#{executor}",
                    "version": {"umbra-core": receipt.get("version", 1)},
                },
                "metadata": {
                    "invocationId": envelope.get("canonical_hash"),
                    "startedOn": receipt.get("generated_at"),
                },
                "byproducts": [
                    {
                        "name": "umbra-remediation-receipt",
                        "mediaType": "application/vnd.umbra.receipt+json",
                        "digest": _digest_from_hash(envelope.get("canonical_hash")),
                    }
                ],
            },
            # Umbra-specific evidence that SLSA has no native field for. Namespaced
            # so it never collides with the standard predicate vocabulary.
            "umbra": {
                "authority_level": receipt.get("authority_level"),
                "authority": receipt.get("authority"),
                "outcome": receipt.get("outcome"),
                "contract_passed": contract_result.get("passed"),
                "verifier_status": verifier.get("status"),
                "verifier_blocked": verifier.get("blocked"),
                "checks_enforcement": checks.get("enforcement"),
                "checks_all_passed": checks.get("all_passed"),
                "trust_boundary_clean": trust_boundary.get("clean"),
                "trust_boundary_quarantined": trust_boundary.get("quarantined_count"),
                "auto_merge": False,
                "human_review_required": True,
                "signature": envelope.get("signature"),
                "public_key": envelope.get("public_key"),
                "signature_algorithm": envelope.get("algorithm", "Ed25519"),
                "key_ephemeral": envelope.get("key_ephemeral"),
            },
        },
    }
    return statement
