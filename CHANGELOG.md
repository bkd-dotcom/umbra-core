# Changelog

All notable changes to **umbra-core** are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Until `1.0.0` the public API may
change between minor versions.

## [0.2.0] — 2026-07-22

### Added — real-time guard (for editor/agent plugins)

- **`umbra guard`** — a fast, deterministic pre-action check for editor/agent
  hooks. Given one proposed file path and/or shell command, it allows or denies
  against the repo's `.umbra/admission.yaml` — instantly, no model, no network.
- Python API: `guard(repo_path, path=..., command=...) -> GuardDecision`.
- `umbra guard --stdin-json --hook-output` emits Claude Code `PreToolUse`
  decision JSON, so a Claude Code plugin hook can **block** an out-of-scope or
  forbidden edit/command *before it happens* — governance from inside the editor,
  run by deterministic code (not the model).
- Blocks dangerous shell patterns (`curl|bash`, `rm -rf /`, reading `.env`/keys,
  `git push`, `gh secret`, …) and checks any file a command writes against scope.

This is the primitive behind the Umbra editor plugins (Claude Code, Cursor,
Codex). It is a pre-flight guard, not a replacement for full admission.

## [0.1.4] — 2026-07-22

### Repository / tooling

- Added `CODEOWNERS`, Dependabot (pip + github-actions), and a CodeQL workflow.
- Automated the GitHub Release: on a version tag, notes are extracted from this
  changelog and the built sdist + wheel are attached (after the PyPI publish).
- Documentation site (MkDocs Material) publishes to GitHub Pages on release.

No functional or security changes to the library since 0.1.3.

## [0.1.3] — 2026-07-22

### Security — defense in depth

- **Layered prompt-injection detection.** Added structural-carrier detection
  (wording-independent): hidden zero-width/bidi unicode, imperatives inside HTML
  comments, role-prompt fences (`<|system|>`), and long base64 blobs that decode
  to imperatives.
- **Full-file quarantine.** When a hidden/obfuscated/encoded carrier is found (or
  `UMBRA_QUARANTINE_MODE=full`), the entire untrusted instruction file is withheld
  from the agent — detection completeness stops mattering.
- **Optional semantic classifier** via `register_semantic_classifier(fn)` — an
  LLM-backed second opinion, off by default, with failures isolated so they never
  break admission.
- **`UMBRA_REQUIRE_SANDBOX`** strict mode: code-executing checks (`npm/pip
  install`, `go/cargo build`) are *blocked* (fail closed) unless a real sandbox is
  available, instead of degrading to host-restricted.

### Added

- `scan_structural`, `register_semantic_classifier` public exports.
- `checks.unsandboxed_code_execution` recorded in every report/receipt.

## [0.1.2] — 2026-07-22

### Security

- **Un-sandboxed code execution caps authority at L1.** A code-executing check
  that ran without a filesystem/network sandbox can no longer earn branch-PR
  authority; a loud warning is logged.
- **MCP path scoping** via `UMBRA_MCP_ROOTS` — `umbra_admit` refuses paths outside
  the allowlisted workspaces.
- **Baseline isolation via `git archive`** (respects `.gitignore`, no symlink
  follow, filters traversal members) instead of `copytree`.
- Dropped `PYTHONPATH`/`NODE_PATH` from the scrubbed check environment.
- SLSA statements stamp `key_ephemeral` / `provenance_trustworthy` so a dev-key
  receipt is never mistaken for attested provenance.
- Expanded Claude Code disallowed tools (`gh api/release/workflow/secret/auth`,
  `curl`/`wget`/`nc`/`ssh`/`scp`/`rsync`).

### Changed

- PyYAML is now a hard dependency for consistent `admission.yaml` parsing.

## [0.1.1] — 2026-07-22

### Security — pre-Marketplace audit fixes

- **Path-matching bypass (P0).** Git paths are read with
  `core.quotePath=false` so non-ASCII names can't evade forbidden globs; malformed,
  quoted, absolute, and traversal paths fail closed (`is_malformed_path`).
- **Case-insensitive forbidden paths (P0).** `Deploy.yml` / `.ENV` /
  `MY_SECRET.txt` can no longer bypass a lowercase forbidden glob on any filesystem.
- **Receipt trust (P0).** `verify_receipt` refuses the public dev-fallback key
  unless an explicit `expected_public_key` is pinned; requires `canonical_hash`;
  rejects an all-zero signing seed.
- **Symlink guard (P1).** `sanitize_checkout`/`restore_checkout` never follow a
  symlinked instruction file out of the checkout.
- **Broader untrusted sources (P1)** — Copilot/Gemini/Cline/Windsurf/Aider configs
  and PR templates are scanned.
- **Authority guard (P1).** A change can no longer earn L2 by weakening a check
  that wasn't clean at baseline.

### Added

- `NullExecutor` (`--agent none`): govern an existing working-tree diff without
  invoking an agent — the CI primitive used by the GitHub Action.

## [0.1.0] — 2026-07-22

### Added — initial public release

- **Agent-agnostic `Executor` protocol** with `CodexExecutor` and
  `ClaudeCodeExecutor`.
- **Admission pipeline** (`run_admission`): executable contract → trust-boundary
  quarantine → required checks → independent verifier → earned authority (0/1/2)
  → Ed25519-signed receipt. `auto_merge` always false.
- **Earned-authority passport** + Emergency Brake (`gate_pr`, `revoke`).
- **SLSA / in-toto provenance** (`to_slsa_provenance`).
- **Append-only Merkle transparency log**.
- **CLI** (`umbra admit/verify/brake/provenance`), **MCP server**, git pre-push
  hook, and a GitHub Action.

> Note: `0.1.0`–`0.1.2` are superseded by `0.1.3`. See [SECURITY.md](SECURITY.md).

[0.2.0]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.2.0
[0.1.4]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.1.4
[0.1.3]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.1.3
[0.1.2]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.1.2
[0.1.1]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.1.1
[0.1.0]: https://github.com/bkd-dotcom/umbra-core/releases/tag/v0.1.0
