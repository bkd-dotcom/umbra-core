# Concepts

## The admission pipeline

Every change is judged by one deterministic pipeline, identical for every agent —
so the verdict depends only on the evidence a run produced, not on which agent ran.

1. **Executable contract** (`.umbra/admission.yaml`) — allowed/forbidden paths,
   diff budget, required checks. Evaluated *outside the model*, fails closed.
   Forbidden paths match case-insensitively; malformed/traversal paths are refused.
2. **Trust boundary** — untrusted instruction files (README, `CLAUDE.md`,
   `.cursorrules`, …) are redacted **on disk before the agent runs**. Detection is
   layered (patterns + structural carriers + optional semantic classifier); a
   hidden/encoded carrier escalates to full-file quarantine.
3. **Required checks** — only allowlisted profiles run, secret-stripped, under the
   strongest isolation that preflights (`sandboxed` / `network-isolated` /
   `host-restricted`). The achieved tier is recorded truthfully.
4. **Independent verifier** — a separate deterministic pass; the patch-writer
   can't self-approve. Blocking checks: contract compliance + secret scan.
5. **Earned authority** — a result of evidence, never a setting.
6. **Signed receipt** — the whole chain, Ed25519-signed.

## Earned authority

| Level | Name | Meaning |
|---|---|---|
| 0 | observe | Contract violated, verifier blocked, or forbidden path touched |
| 1 | analyze | In scope, but required checks didn't run/pass (or nothing safe to propose) |
| 2 | branch_pr | Clean, in scope, checks passed, independently verified → may prepare a branch-only PR |

`auto_merge` is false at every level. A code-executing check that ran without a
real sandbox caps authority at L1 (or is blocked with `UMBRA_REQUIRE_SANDBOX`).

## Receipts & provenance

Each admission seals a **remediation receipt** binding the base commit, contract,
trust-boundary result, diff hash, checks, verifier, executor, and earned
authority. It is **Ed25519-signed** and verified against a *pinned* public key —
so it proves *who* issued it, not merely that some key signed it.

- `to_slsa_provenance(envelope)` maps a receipt to an in-toto Statement + SLSA
  Provenance v1 predicate; the builder id encodes which agent produced the change.
- A `TransparencyLog` appends receipts to an append-only Merkle log that detects
  any rewrite of history.

!!! warning "Signing keys"
    With no `UMBRA_SIGNING_KEY`, a deterministic dev-fallback key is used — its
    seed is public, so such receipts prove nothing to a third party and are
    flagged `key_ephemeral`. Set a production key and pin its public key.

## Executors

An `Executor` is any coding agent adapted to one interface. Ships `codex-cli`,
`claude-code`, and `none` (`NullExecutor`, which governs an existing working-tree
diff without invoking an agent — the CI primitive). Add your own by registering
one adapter; the pipeline never changes.
