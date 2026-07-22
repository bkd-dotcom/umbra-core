# umbra-core

**An agent-agnostic change-control plane for coding agents.**

Coding agents can now change your repository. `umbra-core` is the layer that
decides how much authority a given change has earned — and proves it — for
**any** agent. Codex, Claude Code, Cursor, or a future agent are all governed by
one admission pipeline and adapted behind a single interface:

```
Executor (protocol)
  ├── CodexExecutor        →  codex exec  (disposable checkout, no push/merge)
  ├── ClaudeCodeExecutor   →  claude -p   (--bare: no CLAUDE.md auto-read, push/merge tools denied)
  └── <your agent>         →  one adapter, no pipeline change
```

The governing insight: **a coding agent cannot approve its own authority to make
a change.** The patch-writer is never the patch-approver. `umbra-core` is the
layer that can decide — agent-agnostically — and seals every decision in a
signed receipt.

## Why this is agent-agnostic (and why that matters)

Tools like Claude Code and Codex can *find* and *fix* issues — that's the
commoditized half. None of them govern *themselves*: none decide whether an
agent is **allowed** to make a change, quarantine untrusted repo text before the
agent reads it, verify the result independently, or emit a cryptographic proof
of the authority earned. `umbra-core` sits one layer above every agent and does
exactly that.

Claude Code runs `--bare`, so it does **not** auto-ingest `CLAUDE.md` — the
trust boundary, not the agent, decides what untrusted repository text the agent
may see. Push/commit/merge tools are refused at the CLI layer, so a governed run
can only ever *propose* a change.

## Executor interface

```python
from umbra_core import resolve_available, get_executor

# pick the first available agent (honoring a preference order)
agent = resolve_available(["claude-code", "codex-cli"])

# or ask for one explicitly
agent = get_executor("claude-code")

result = agent.propose("bump the vulnerable dependency", repo_path=checkout)
print(result.executor)         # "claude-code" | "codex-cli" | "unavailable"
print(result.diff)             # recomputed from git on the final tree
print(result.model_identity)   # honest provenance for the receipt
```

Enable agents via environment flags (off by default, fail-closed):

- `UMBRA_ENABLE_CODEX_CLI=true` (+ `codex login`)
- `UMBRA_ENABLE_CLAUDE_CODE=true` (+ authenticated `claude` CLI)

## The admission pipeline

One governed, deterministic pipeline runs before any change is trusted — and it
is **identical for every executor**, so the verdict depends only on the evidence
the run produced, never on which agent ran:

```
load executable contract (.umbra/admission.yaml)
  → redact untrusted repository text on disk (README / AGENTS.md / CLAUDE.md / …)
  → run required checks on the BASE commit (isolated worktree: regression vs pre-existing)
  → run the bounded task via ANY Executor in a disposable checkout
  → evaluate the changeset against the contract (deterministic, outside the model)
  → re-run required checks on the CHANGED tree (allowlisted profiles, secret-stripped env)
  → independently verify it (the patch-writer can't self-approve)
  → grant only the authority the run EARNED (0 observe · 1 analyze · 2 branch-PR)
  → seal it in an Ed25519-signed Remediation Receipt
```

```python
from pathlib import Path
from umbra_core import get_executor, run_admission, build_receipt, verify_receipt

agent = get_executor("claude-code")
report = run_admission(
    repo_path=Path(checkout),
    repo_label="acme/app",
    mission="update the vulnerable dependency to its fixed version; change only manifests",
    executor=agent,
)
print(report.authority_level, report.authority)   # e.g. 2 branch_pr
print(report.outcome)

# seal + independently verify the signed receipt
envelope = build_receipt(
    repo=report.repo, base_commit=report.base_commit, contract=report.contract,
    contract_result=report.contract_result, verifier=report.verifier,
    trust_boundary=report.trust_boundary, proposed_change=report.proposed_change,
    providers=report.providers, authority_level=report.authority_level,
    authority=report.authority, executor=report.executor, diff=report.diff,
    checks=report.checks, model_identity=report.model_identity, outcome=report.outcome,
)
assert verify_receipt(envelope)["verified"] is True   # issued by this instance, untampered
```

Earned authority is a **result of evidence, never a setting**: a forbidden-path
change or an introduced secret caps at `observe (0)`; an in-scope change whose
required checks didn't run/pass caps at `analyze (1)`; only a clean, in-scope,
checks-passed, independently-verified change earns `branch_pr (2)`. `auto_merge`
is false at every level.

Set `UMBRA_SIGNING_KEY` (base64 of >=32 raw bytes) for a stable production
signing key; without it a deterministic dev key is used and every receipt is
honestly flagged `key_ephemeral`.

## Run from source

```bash
uv venv
uv pip install -e ".[dev]"
uv run pytest        # hermetic — no real agent invoked, no network
```

## Status

Early. This repo extracts the governance core of [Umbra](https://umbra.engineer)
into an agent-agnostic package. The executor layer and the full admission
pipeline (contract → trust boundary → checks → verifier → earned authority →
Ed25519-signed receipt) are in place and driven by any `Executor`.

## License

[MIT](LICENSE) © 2026 Binay Dalai.
