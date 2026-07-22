# GitHub Action

**Umbra Admission** governs every pull request — from Claude Code, Codex, Cursor,
Copilot, Devin, or a human — and attaches a signed receipt. On the
[GitHub Marketplace](https://github.com/marketplace/actions/umbra-admission).

## Usage

```yaml
name: Umbra Admission
on:
  pull_request:
permissions:
  contents: read
  pull-requests: write
jobs:
  admit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0                       # base must be reachable for the diff
      - uses: bkd-dotcom/umbra-action@v1
        with:
          min-authority: "1"                   # 0 observe · 1 analyze · 2 branch-PR
          signing-key: ${{ secrets.UMBRA_SIGNING_KEY }}   # optional: stable receipts
```

Make **"Umbra Admission"** a *required status check* in branch protection (enable
it for administrators too) and nothing merges without a receipt.

## Inputs

| Input | Default | Description |
|---|---|---|
| `mission` | review prompt | The bounded task the change claims to perform. |
| `min-authority` | `1` | Fail unless the change earns at least this level (0/1/2). |
| `agent` | `""` | Force `codex-cli`/`claude-code` to re-run; blank governs the existing diff. |
| `signing-key` | `""` | Base64 Ed25519 key (32+ bytes) for stable receipts. |
| `require-sandbox` | `false` | Fail closed if code-executing checks can't run sandboxed. |
| `umbra-version` | latest | Pin a specific `umbra-core` version. |
| `python-version` | `3.12` | Python to run on. |

## Behavior

The action stages the PR's change as a working-tree diff, runs `umbra admit`,
posts the verdict as a PR comment, uploads the signed receipt as an artifact, and
fails the check below the required authority. On Linux it installs bubblewrap so
checks run **sandboxed** by default (the achieved tier is recorded in the receipt).

Pin `@v1` (moving major) or an exact `@v0.1.3+` tag. `auto_merge` is always false.
