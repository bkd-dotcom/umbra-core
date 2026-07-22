# Security Policy

umbra-core is a security tool, so we hold its own security to a high bar.

## Supported versions

Fixes land on the latest minor release published to
[PyPI](https://pypi.org/project/umbra-core/). Always run the latest.

| Version | Supported |
|---|---|
| `>= 0.1.3` | ✅ (current — includes all published hardening) |
| `0.1.0`–`0.1.2` | ⚠️ superseded — upgrade to the latest |

`0.1.0`–`0.1.2` contain issues fixed in later releases (path-matching bypasses,
dev-key verification trust, and — in the companion GitHub Action `< v0.1.3` — a
workflow script-injection sink). Pin the Action to `@v1` (which moves forward) or
`@v0.1.3+`, and install `umbra-core>=0.1.3`.

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Use GitHub's private vulnerability reporting:
**https://github.com/bkd-dotcom/umbra-core/security/advisories/new**

Include, where possible: affected version, a minimal reproduction (a crafted
`.umbra/admission.yaml`, repo layout, or receipt), the impact (e.g. scope bypass,
authority escalation, receipt forgery, secret exposure), and any suggested fix.
We aim to acknowledge within a few days and to fix confirmed issues promptly, then
credit reporters who wish to be named.

## Threat model & honest scope

Read this before relying on umbra-core for a security guarantee.

- **What it enforces.** An executable contract (allowed/forbidden paths, diff
  budget, required checks) evaluated *outside the model* and fail-closed; an
  independent verifier the patch-writer can't self-approve; earned authority
  (0/1/2) that is a result of evidence; and an Ed25519-signed receipt.
- **Prompt injection is *mitigated*, not solved.** Detection is layered
  (imperative patterns over normalized text + structural carriers + optional
  semantic classifier) with full-file quarantine when a hidden/encoded carrier is
  found. No detector defeats all injection — the durable protection is the
  architecture (on-disk quarantine + contract + verifier + authority cap), which
  bounds a change even if every detection layer misses.
- **Check isolation is best-effort by platform.** Checks run under the strongest
  tier that *preflights* — `sandboxed` (Linux bubblewrap), `network-isolated`
  (`unshare -rn`), or `host-restricted` (allowlist + secret-stripped env only).
  The achieved tier is recorded truthfully in every receipt. A code-executing
  check that runs un-sandboxed caps authority at L1; set
  `UMBRA_REQUIRE_SANDBOX=true` to fail closed instead.
- **Receipt trust requires a real key.** With no `UMBRA_SIGNING_KEY`, signing uses
  a deterministic **dev-fallback key whose seed is public in the source tree** —
  such a receipt proves nothing to a third party and is flagged `key_ephemeral`.
  `verify_receipt` refuses the dev key unless an explicit `expected_public_key` is
  pinned. **Set a production `UMBRA_SIGNING_KEY` and publish/pin its public key.**
- **Not a replacement for code review.** umbra-core is the governance layer
  between the agent and the human; a human still merges. `auto_merge` is always
  false.

## Hardening recommendations for operators

- Set a managed `UMBRA_SIGNING_KEY` (base64 of ≥32 random bytes) and pin its
  public key in whatever verifies receipts.
- Run checks on Linux with bubblewrap available (the Action installs it) so the
  tier is `sandboxed`; use `UMBRA_REQUIRE_SANDBOX=true` for fail-closed CI.
- Own and version your `.umbra/admission.yaml` (`policy_owner` / `policy_version`).
- Make the admission status check **required** in branch protection, and enable
  it for administrators too, so nothing merges without a receipt.
