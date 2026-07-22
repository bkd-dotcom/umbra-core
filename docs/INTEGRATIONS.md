# Integrating umbra-core everywhere

umbra-core governs coding agents from wherever their change tries to reach your
repository. It is **agent-agnostic** — the same `run_admission()` core drives
every surface — so you install the checkpoint once and it governs Claude Code,
Codex, Cursor, Copilot, Devin, or a human, identically.

> Design principle: umbra-core sits **above** the agent, never inside it. An
> agent cannot approve its own authority, so putting the governance layer *in*
> the agent would defeat the purpose. Every surface below is a checkpoint the
> agent's change must pass through.

## 1. PyPI package (the foundation)

```bash
pip install umbra-core           # or: uv pip install umbra-core
```

```python
from pathlib import Path
from umbra_core import get_executor, run_admission, build_receipt, verify_receipt

agent = get_executor("claude-code")           # or "codex-cli"
report = run_admission(Path("checkout"), "acme/app",
                       "bump the vulnerable dependency; change only manifests", agent)
print(report.authority_level, report.outcome)  # e.g. 2 branch_pr
```

## 2. CLI + git hook (governs the agent on the developer's machine)

```bash
umbra admit . --mission "bump left-pad to its fixed version" --agent claude-code
umbra verify receipt.json
umbra provenance receipt.json          # -> in-toto/SLSA statement
umbra brake acme app --store passports.json --reason "incident-42"
```

`umbra admit` exits non-zero unless the change earns branch-PR authority (tune
with `--min-authority`), so it gates a **pre-push hook**:

```bash
# install the hook in any repo
git config core.hooksPath integrations/git-hooks
# then a push runs admission first:
UMBRA_MISSION="review pending change" git push
UMBRA_SKIP=1 git push        # bypass once
```

## 3. GitHub App / Action (the highest-reach checkpoint — governs ANY agent's PR)

Drop `integrations/github-action/example-workflow.yml` at
`.github/workflows/umbra.yml` in any repo:

```yaml
on:
  pull_request:
jobs:
  admit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with: { ref: ${{ github.event.pull_request.head.sha }}, fetch-depth: 0 }
      - uses: bkd-dotcom/umbra-action@v1
        with:
          min-authority: "1"
          signing-key: ${{ secrets.UMBRA_SIGNING_KEY }}
```

Every PR — no matter which agent opened it — gets an admission run, a verdict
comment, and a signed receipt artifact. Make **"Umbra Admission"** a *required
status check* in branch protection and nothing merges without a receipt.
`auto_merge` is always false — Umbra governs the agent; a human merges.

## 4. MCP server (agents call governance themselves)

```bash
pip install "umbra-core[mcp]"
python -m umbra_core.mcp_server            # stdio transport
```

Register the command with an MCP client (Claude Code, Cursor). The agent can
then call `umbra_admit`, `umbra_verify`, and `umbra_provenance` to run its own
change through the deterministic pipeline *before* proposing it — the verdict is
still produced outside the model.

## 5. Hosted API + dashboard

The reference hosted deployment is [Umbra](https://umbra.engineer). To self-host,
wrap `run_admission` in your API framework of choice and persist passports with a
`PassportStore` (a `JsonFilePassportStore` ships in the box; implement the
`PassportStore` protocol for a database).

## Which surface should I start with?

| Goal | Start here |
|---|---|
| Govern every agent with the least work | **GitHub Action** (surface 3) |
| Govern on the developer's machine | **CLI + git hook** (surface 2) |
| Let others build on it | **PyPI** (surface 1) |
| Agents that speak MCP | **MCP server** (surface 4) |
| A product with a UI | **Hosted API** (surface 5) |
