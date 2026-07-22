# Contributing to umbra-core

Thanks for helping govern coding agents. This project is small, deterministic,
and security-sensitive — contributions are very welcome, with a few guardrails.

## Development setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/bkd-dotcom/umbra-core
cd umbra-core
uv sync --extra dev          # installs the package + test tooling
uv run pytest                # run the suite
uv run ruff check .          # lint
```

Run the prompt-injection defense demo (offline, deterministic):

```bash
uv run python demos/injection/demo.py
```

## Before you open a PR

- **Add tests.** Every behavior change needs a test; security-relevant paths
  (contract matching, checks allowlist/sandbox, verifier, receipts, trust
  boundary) must be covered. Aim to keep or raise coverage.
- **Keep the core deterministic and dependency-light.** The pipeline
  (`contract`, `checks`, `verifier`, `receipt`, `trust_boundary`, `admission`)
  must not call a model or the network. Model/agent interaction lives only behind
  the `Executor` protocol; the LLM injection classifier is an *optional* hook.
- **Preserve the invariants.** `auto_merge` is always false. Authority is earned
  from evidence, never set. The verifier never fabricates a pass. Receipts verify
  against a *pinned* key. If a change touches these, call it out explicitly.
- **Be honest in output and docs.** No overclaiming — enforcement tiers, model
  provenance, and detection scope are reported truthfully. Match that tone.
- `uv run pytest` and `uv run ruff check .` must pass.

## This repo governs itself

`main` is protected and every PR runs **Umbra self-admission** (plus the test
matrix) as a required check — the change must stay within
[`.umbra/admission.yaml`](.umbra/admission.yaml) and earn authority to merge. If
your PR touches a forbidden path, expect the check to block it; that's the tool
working. A maintainer merges (branch-only, never auto-merge).

## Reporting security issues

Do **not** open a public issue. See [SECURITY.md](SECURITY.md) — use private
vulnerability reporting.

## License

By contributing you agree your contributions are licensed under the project's
[MIT License](LICENSE).
