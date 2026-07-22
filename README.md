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

## Run from source

```bash
uv venv
uv pip install -e ".[dev]"
uv run pytest        # hermetic — no real agent invoked, no network
```

## Status

Early. This repo extracts the governance core of [Umbra](https://umbra.engineer)
into an agent-agnostic package. The executor layer is first; the admission
pipeline (contract → trust boundary → checks → verifier → earned authority →
Ed25519-signed receipt) follows.

## License

[MIT](LICENSE) © 2026 Binay Dalai.
