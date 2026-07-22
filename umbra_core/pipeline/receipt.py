"""Signed Remediation Receipt — a proof-carrying record of one agent-proposed change.

Gathers the accountability chain for a single change (repo + base commit, the
contract that applied, the trust-boundary result, the exact diff, the independent
verifier result, the earned authority, the executor + model provenance),
canonicalizes it, and signs it with an Ed25519 key.

Why signing, not just a hash: a bare SHA-256 proves a document wasn't
*accidentally* altered, but anyone can recompute it after editing. An Ed25519
signature proves the receipt was produced by the holder of the private key and
has not changed since. ``verify_receipt`` checks the signature against a *pinned*
public key, so an attacker minting a self-consistent envelope with their own
keypair proves nothing.

Honesty: the receipt records whether the signing key is a managed production key
or the deterministic dev fallback (``key_ephemeral``). Invariant: ``auto_merge``
is always false.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime
from typing import Any


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def signing_seed() -> bytes:
    """32-byte Ed25519 private seed used to sign receipts.

    Production sets ``UMBRA_SIGNING_KEY`` (base64 of >=32 raw bytes) so receipts
    verify against a stable public key across restarts. The dev fallback is
    deterministic so local runs/tests round-trip — it is NOT a real secret.
    """
    provided = os.getenv("UMBRA_SIGNING_KEY")
    if provided:
        try:
            seed = base64.b64decode(provided)
            if len(seed) >= 32:
                candidate = seed[:32]
                # Reject obviously weak seeds so a copy-pasted "default" can't be
                # trusted as a production key.
                if candidate != b"\x00" * 32:
                    return candidate
        except Exception:  # noqa: BLE001 - malformed env → dev seed
            pass
    return hashlib.sha256(b"umbra-core-dev-insecure-signing-seed").digest()


def signing_key_is_ephemeral() -> bool:
    """True when signing uses the deterministic dev seed (no valid UMBRA_SIGNING_KEY)."""
    provided = os.getenv("UMBRA_SIGNING_KEY")
    if not provided:
        return True
    try:
        seed = base64.b64decode(provided)
        return len(seed) < 32 or seed[:32] == b"\x00" * 32
    except Exception:  # noqa: BLE001
        return True


def _private_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(signing_seed())


def public_key_b64() -> str:
    """Base64 of the raw 32-byte Ed25519 public key (publish this for verification)."""
    from cryptography.hazmat.primitives import serialization

    pub = _private_key().public_key()
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def sign(canonical_text: str) -> str:
    return base64.b64encode(_private_key().sign(canonical_text.encode("utf-8"))).decode()


def verify_signature(canonical_text: str, signature_b64: str, public_key_b64_str: str | None = None) -> bool:
    """Verify an Ed25519 signature over ``canonical_text`` against a public key
    (defaults to this instance's key). Never raises."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        raw = base64.b64decode(public_key_b64_str or public_key_b64())
        sig = base64.b64decode(signature_b64)
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, canonical_text.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def build_receipt(
    *,
    repo: str,
    base_commit: str | None,
    contract: dict[str, Any],
    contract_result: dict[str, Any],
    verifier: dict[str, Any] | None,
    trust_boundary: dict[str, Any] | None,
    proposed_change: dict[str, Any] | None,
    providers: dict[str, str] | None,
    authority_level: int,
    authority: str,
    executor: str | None = None,
    diff: str | None = None,
    diff_hash: str | None = None,
    checks: dict[str, Any] | None = None,
    baseline_checks: dict[str, Any] | None = None,
    check_diagnosis: dict[str, Any] | None = None,
    model_identity: dict[str, Any] | None = None,
    context_manifest: dict[str, Any] | None = None,
    human_decision: str | None = None,
    pr_url: str | None = None,
    outcome: str | None = None,
) -> dict[str, Any]:
    """Assemble and sign a Remediation Receipt.

    Returns ``{receipt, canonical_hash, signature, public_key, algorithm,
    key_ephemeral}``. The signature covers the canonical JSON of ``receipt``
    (which binds the base commit, diff hash, executed checks, verifier, executor,
    and model identity), so signing transitively binds those artifacts.
    """
    receipt: dict[str, Any] = {
        "kind": "umbra.remediation-receipt",
        "version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "repo": repo,
        "base_commit": base_commit,
        "executor": executor,
        "policy_hash": contract_result.get("contract_hash"),
        "contract": contract,
        "contract_result": contract_result,
        "trust_boundary": trust_boundary,
        "verifier": verifier,
        "checks": checks,
        "baseline_checks": baseline_checks,
        "check_diagnosis": check_diagnosis,
        "model_identity": model_identity,
        "context_manifest": context_manifest,
        "proposed_change": proposed_change,
        "provider_ledger": providers or {},
        "diff_hash": (_sha256(diff) if diff else None) or diff_hash,
        "authority_level": authority_level,
        "authority": authority,
        "human_decision": human_decision,
        "pr_url": pr_url,
        "outcome": outcome,
        # Invariants, stated in the signed payload so they can't be quietly dropped.
        "auto_merge": False,
        "human_review_required": True,
    }
    canonical = _canonical(receipt)
    canonical_hash = _sha256(canonical)
    signature = sign(canonical)
    return {
        "receipt": receipt,
        "canonical_hash": canonical_hash,
        "signature": signature,
        "public_key": public_key_b64(),
        "algorithm": "Ed25519",
        "key_ephemeral": signing_key_is_ephemeral(),
    }


def verify_receipt(envelope: dict[str, Any], *, expected_public_key: str | None = None) -> dict[str, Any]:
    """Independently verify a signed receipt envelope.

    Recomputes the canonical hash of ``envelope['receipt']`` and checks the
    signature **against the pinned public key** (``expected_public_key`` or this
    instance's key) — NOT the key embedded in the envelope. ``issued_by_umbra`` is
    true only when the signature verifies against the pinned key.

    Security: if no ``expected_public_key`` is given AND this instance is using
    the deterministic dev-fallback key (``UMBRA_SIGNING_KEY`` unset/invalid), we
    REFUSE to verify — the dev key's seed is public in the source tree, so
    anyone could mint a "valid" receipt. A real verification requires either an
    explicit pinned key or a production ``UMBRA_SIGNING_KEY``. Also requires the
    envelope to carry a ``canonical_hash`` (no hash → not verified).
    """
    receipt = envelope.get("receipt")
    signature = envelope.get("signature")
    claimed_hash = envelope.get("canonical_hash")
    embedded_key = envelope.get("public_key")
    if not isinstance(receipt, dict) or not signature:
        return {"verified": False, "hash_matches": False, "signature_valid": False,
                "issued_by_umbra": False, "reason": "Receipt or signature missing."}

    # Fail closed when the pinned key would be the public dev-fallback key.
    if expected_public_key is None and signing_key_is_ephemeral():
        return {
            "verified": False, "hash_matches": False, "signature_valid": False,
            "issued_by_umbra": False, "key_ephemeral": True,
            "reason": (
                "Refusing to verify against the dev-fallback key (its seed is public). "
                "Set a production UMBRA_SIGNING_KEY, or pass expected_public_key/--public-key "
                "to verify against a known key."
            ),
        }

    pinned_key = expected_public_key or public_key_b64()
    canonical = _canonical(receipt)
    computed_hash = _sha256(canonical)
    hash_matches = bool(claimed_hash) and claimed_hash == computed_hash

    issued_by_umbra = verify_signature(canonical, str(signature), pinned_key)
    key_matches = bool(embedded_key) and embedded_key == pinned_key

    return {
        # Require BOTH a valid signature against the pinned key AND a matching
        # claimed hash. A receipt with no canonical_hash is not considered verified.
        "verified": bool(issued_by_umbra and hash_matches),
        "issued_by_umbra": issued_by_umbra,
        "signature_valid": issued_by_umbra,
        "hash_matches": hash_matches,
        "key_matches_pinned": key_matches,
        "computed_hash": computed_hash,
        "claimed_hash": claimed_hash,
        "expected_public_key": pinned_key,
        "algorithm": envelope.get("algorithm", "Ed25519"),
        "key_ephemeral": envelope.get("key_ephemeral"),
    }
