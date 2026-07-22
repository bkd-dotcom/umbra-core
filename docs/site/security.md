# Security

umbra-core is a security tool; we hold its own security to a high bar. The full
policy (supported versions, **private** vulnerability reporting) is in
[`SECURITY.md`](https://github.com/bkd-dotcom/umbra-core/security/policy).

## Report a vulnerability

Do **not** open a public issue. Use private reporting:
<https://github.com/bkd-dotcom/umbra-core/security/advisories/new>

## Honest scope

Read this before relying on umbra-core for a guarantee.

- **What it enforces.** A fail-closed executable contract, an independent verifier
  the patch-writer can't self-approve, earned authority from evidence, and an
  Ed25519-signed receipt. `auto_merge` is always false.
- **Prompt injection is mitigated, not solved.** Detection is layered (patterns +
  structural carriers + optional classifier) with full-file quarantine on hidden
  carriers. No detector defeats all injection — the durable protection is the
  architecture (on-disk quarantine + contract + verifier + authority cap), which
  bounds a change even if every detection layer misses.
- **Check isolation is best-effort by platform.** The achieved tier
  (`sandboxed` / `network-isolated` / `host-restricted`) is recorded truthfully in
  every receipt. A code-executing check that runs un-sandboxed caps authority at
  L1; set `UMBRA_REQUIRE_SANDBOX=true` to fail closed.
- **Receipt trust requires a real key.** The dev-fallback key's seed is public;
  such receipts are flagged `key_ephemeral` and `verify_receipt` refuses them
  unless a key is pinned. Set a production `UMBRA_SIGNING_KEY`.
- **Not a replacement for code review** — it's the governance layer between the
  agent and the human.

## Supported versions

Run the latest. `0.1.0`–`0.1.2` are superseded by `0.1.3`; pin the Action to
`@v1` or `@v0.1.3+`.
