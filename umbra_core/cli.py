"""The ``umbra`` command-line interface.

One entry point over the agent-agnostic core, so the same governance runs on a
developer's machine, in a git hook, and in CI:

    umbra admit  <repo> --agent claude-code --mission "..."   # govern an agent's change
    umbra verify <receipt.json>                                # verify a signed receipt
    umbra brake  <owner> <repo> --store passports.json         # Emergency Brake -> L0
    umbra provenance <receipt.json>                            # emit SLSA/in-toto statement
    umbra gates <receipt.json>                                 # G1/G2/G3 proof-gate summary
    umbra comment <report.json>                                # render the canonical PR comment
    umbra admit-extension <skill-or-mcp-dir>                    # govern a skill / MCP extension
    umbra init                                                 # scaffold .umbra/admission.yaml
    umbra completion zsh                                        # shell completion script

``admit`` exits non-zero unless the run earns branch-PR authority (L2), so it
gates a pre-push hook or a CI required check. ``--min-authority`` tunes the bar.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import (
    JsonFilePassportStore,
    build_receipt,
    get_executor,
    guard,
    issue_passport,
    resolve_available,
    revoke,
    run_admission,
    scan_repository,
    to_slsa_provenance,
    verify_receipt,
)


def _print(obj: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, default=str))


def _receipt_from_report(report) -> dict[str, Any]:
    return build_receipt(
        repo=report.repo, base_commit=report.base_commit, contract=report.contract,
        contract_result=report.contract_result, verifier=report.verifier,
        trust_boundary=report.trust_boundary, proposed_change=report.proposed_change,
        providers=report.providers, authority_level=report.authority_level,
        authority=report.authority, executor=report.executor, diff=report.diff,
        checks=report.checks, baseline_checks=report.baseline_checks,
        check_diagnosis=report.check_diagnosis, model_identity=report.model_identity,
        context_manifest=report.context_manifest, outcome=report.outcome,
    )


def cmd_admit(args: argparse.Namespace) -> int:
    repo_path = Path(args.repo).resolve()
    if not repo_path.is_dir():
        print(f"error: {repo_path} is not a directory", file=sys.stderr)
        return 2

    # Resolve the executor: explicit --agent, else first available, else fail clearly.
    if args.agent:
        try:
            executor = get_executor(args.agent)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not executor.available():
            print(
                f"error: agent {args.agent!r} is not available. Enable + authenticate it "
                "(e.g. UMBRA_ENABLE_AIDER=true / UMBRA_ENABLE_CLAUDE_CODE=true / "
                "UMBRA_ENABLE_CODEX_CLI=true).",
                file=sys.stderr,
            )
            return 2
    else:
        executor = resolve_available(args.prefer.split(",") if args.prefer else None)
        if executor is None:
            print(
                "error: no coding agent is available. Enable one with "
                "UMBRA_ENABLE_AIDER=true, UMBRA_ENABLE_CLAUDE_CODE=true, or "
                "UMBRA_ENABLE_CODEX_CLI=true, "
                "or pass --agent.",
                file=sys.stderr,
            )
            return 2

    report = run_admission(repo_path, args.label or repo_path.name, args.mission, executor)
    envelope = _receipt_from_report(report)

    # Persist the earned-authority passport when a store is given.
    if args.store:
        store = JsonFilePassportStore(args.store)
        store.save(args.owner, report.repo, issue_passport(report, receipt_hash=envelope["canonical_hash"]))

    if args.receipt_out:
        Path(args.receipt_out).write_text(json.dumps(envelope, indent=2, default=str))

    payload = {"report": report.to_public(), "receipt": envelope}
    if args.json:
        _print(payload, True)
    else:
        print(f"repo        : {report.repo}")
        print(f"agent       : {report.executor}")
        print(f"changed     : {', '.join(report.changed_files) or '(none)'}")
        print(f"contract    : {'PASS' if report.contract_result['passed'] else 'VIOLATED'}")
        tb = report.trust_boundary
        print(f"trust bound.: {'clean' if tb['clean'] else str(tb['quarantined_count']) + ' line(s) quarantined'}")
        if report.verifier:
            print(f"verifier    : {'BLOCKED' if report.verifier['blocked'] else 'reviewable'}")
        checks = report.checks or {}
        print(f"checks      : ran={checks.get('ran')} all_passed={checks.get('all_passed')} enforcement={checks.get('enforcement')}")
        print(f"authority   : L{report.authority_level} ({report.authority})")
        print(f"outcome     : {report.outcome}")
        print(f"receipt     : {envelope['canonical_hash']}  (key_ephemeral={envelope['key_ephemeral']})")

    # Exit code gates hooks/CI: non-zero unless the run met the authority bar.
    return 0 if report.authority_level >= args.min_authority else 1


def cmd_scan(args: argparse.Namespace) -> int:
    """Layered SAST over a repository — the detection floor that reaches parity
    with LLM scanners while staying offline and deterministic by default.

    Accepts a local path OR a git URL (shallow-cloned to a disposable checkout,
    like a hosted scanner). Emits text, ``--json``, or ``--sarif`` (the GitHub
    code-scanning standard). Exits non-zero when a finding meets/exceeds
    ``--fail-on`` severity, so it can gate CI."""
    from . import __version__
    from .pipeline.findings.fetch import resolve_scan_target
    from .pipeline.findings.model import Severity
    from .pipeline.findings.sarif import to_sarif

    fix_proposals = None
    try:
        with resolve_scan_target(args.repo, depth=args.depth) as root:
            if not root.exists():
                print(f"error: path not found: {root}", file=sys.stderr)
                return 2
            report = scan_repository(root, use_semgrep=args.semgrep, semgrep_config=args.semgrep_config,
                                     use_treesitter=getattr(args, "treesitter", False))
            # --fix: propose governed, receipted fixes INSIDE the checkout (the
            # disposable clone still exists here; admission runs in it).
            if getattr(args, "fix", False) and report.findings:
                from .pipeline.findings.fusion import propose_fixes
                fix_proposals = propose_fixes(
                    root, report.findings, max_fixes=args.max_fixes,
                    agent=getattr(args, "fix_agent", None),
                )
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.sarif:
        payload = json.dumps(to_sarif(report, tool_version=__version__), indent=2)
        if args.output:
            Path(args.output).write_text(payload)
            print(f"wrote SARIF: {args.output} ({len(report.findings)} result(s))", file=sys.stderr)
        else:
            print(payload)
    elif args.json:
        payload = json.dumps(report.to_public(), indent=2, default=str)
        if args.output:
            Path(args.output).write_text(payload)
            print(f"wrote JSON: {args.output}", file=sys.stderr)
        else:
            print(payload)
    else:
        counts = report.counts()
        print(f"umbra scan {args.repo} — {len(report.findings)} finding(s) across "
              f"{report.files_scanned} file(s) [{', '.join(report.layers)}]")
        for f in report.findings:
            cwe = f" {f.cwe}" if f.cwe else ""
            print(f"  {f.severity.value.upper():8} {f.file}:{f.line} "
                  f"[{f.category}]{cwe} — {f.title} (conf {f.confidence:.2f})")
        if report.layers_unavailable:
            print(f"  (layers not run: {', '.join(report.layers_unavailable)})")
        shown = ", ".join(f"{k}={v}" for k, v in counts.items() if v)
        if shown:
            print(f"  summary: {shown}")

    # --fix: report governed fix proposals (JSON adds a `fixes` array).
    if fix_proposals is not None:
        if args.json or args.sarif:
            # Append fusion output as a separate JSON object on stderr-free stdout.
            print(json.dumps({"fixes": [fp.to_public() for fp in fix_proposals]},
                             indent=2, default=str))
        else:
            print(f"\nGoverned fix proposals ({len(fix_proposals)}):")
            for fp in fix_proposals:
                r = fp.report
                rh = (fp.receipt or {}).get("canonical_hash", "")
                tag = "branch-PR ready" if fp.branch_pr_ready else "analyze"
                print(f"  {fp.finding.category} @ {fp.finding.file}:{fp.finding.line} "
                      f"→ L{r.authority_level} ({r.authority}) · {tag}"
                      + (f" · receipt {rh[:16]}…" if rh else ""))
            print("  (auto_merge: never · each proposal is admission-governed and receipt-sealed)")

    if args.fail_on:
        threshold = Severity(args.fail_on).rank
        offending = [f for f in report.findings if f.severity.rank >= threshold]
        if offending:
            print(f"FAIL: {len(offending)} finding(s) at or above {args.fail_on}", file=sys.stderr)
            return 1
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        envelope = json.loads(Path(args.receipt).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read receipt: {exc}", file=sys.stderr)
        return 2
    result = verify_receipt(envelope, expected_public_key=args.public_key)
    if args.json:
        _print(result, True)
    else:
        ok = result["verified"]
        if not ok and result.get("reason"):
            print("NOT VERIFIED  — " + result["reason"])
        else:
            print(("VERIFIED" if ok else "NOT VERIFIED") + f"  (issued_by_umbra={result['issued_by_umbra']}, hash_matches={result['hash_matches']})")
    return 0 if result["verified"] else 1


def cmd_brake(args: argparse.Namespace) -> int:
    store = JsonFilePassportStore(args.store)
    rec = revoke(store, args.owner, args.repo, reason=args.reason)
    if args.json:
        _print(rec, True)
    else:
        print(f"Emergency Brake applied: {args.owner}/{args.repo} -> L{rec['authority_level']} ({rec['authority']})")
    return 0


def cmd_provenance(args: argparse.Namespace) -> int:
    try:
        envelope = json.loads(Path(args.receipt).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read receipt: {exc}", file=sys.stderr)
        return 2
    stmt = to_slsa_provenance(envelope)
    print(json.dumps(stmt, indent=2, default=str))
    return 0


def cmd_gates(args: argparse.Namespace) -> int:
    """Print the G1/G2/G3 proof-gate summary for a signed receipt.

    G1 capability integrity · G2 behavioral authenticity · G3 interaction
    auditability. Exit non-zero unless all gates pass (so it can gate CI)."""
    from .pipeline import evaluate_gates

    try:
        envelope = json.loads(Path(args.receipt).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read receipt: {exc}", file=sys.stderr)
        return 2
    summary = evaluate_gates(envelope)
    if args.json:
        print(json.dumps(summary.to_public(), indent=2, default=str))
    else:
        for g in summary.gates:
            mark = {"pass": "PASS", "fail": "FAIL", "unproven": "UNPROVEN"}.get(g.status, g.status.upper())
            print(f"  {g.id} {g.name:<24} [{mark}] {g.reason}")
        print(f"  → all gates pass: {summary.all_pass}")
    return 0 if summary.all_pass else 1


def cmd_comment(args: argparse.Namespace) -> int:
    """Render the canonical Umbra PR-comment markdown from an ``admit --json`` payload.

    Reads the ``{report, receipt}`` JSON (from a file or stdin) and prints the exact
    PR-comment template the architecture freezes, so the GitHub Action and every
    other surface render the identical pack."""
    from .pipeline import render_pr_comment

    try:
        text = sys.stdin.read() if args.report in (None, "-") else Path(args.report).read_text()
        payload = json.loads(text or "{}")
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read report payload: {exc}", file=sys.stderr)
        return 2
    print(render_pr_comment(payload))
    return 0


def cmd_admit_extension(args: argparse.Namespace) -> int:
    """Govern an agent extension (a skill dir or an MCP server manifest): fingerprint
    its bytes, quarantine its documentation/tool descriptions, and admit or deny.

    Exit non-zero on deny, so it can gate a plugin-install hook or CI."""
    from .pipeline import admit_extension, asbom, load_contract

    root = Path(args.path)
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    contract = load_contract(args.repo) if args.repo else None
    ext = admit_extension(root, kind=args.kind, contract=contract, allow_quarantined=args.allow_quarantined)

    if args.asbom:
        print(json.dumps(asbom([ext], org=args.org), indent=2, default=str))
    elif args.json:
        print(json.dumps(ext.to_public(), indent=2, default=str))
    else:
        print(f"extension : {ext.name} ({ext.kind} v{ext.version})")
        print(f"verdict   : {ext.verdict.upper()}")
        print(f"hash      : {ext.extension_hash}")
        print(f"files     : {len(ext.files)}")
        if ext.mcp_tools:
            print(f"mcp tools : {', '.join(ext.mcp_tools)}")
        if ext.quarantine_findings:
            print(f"quarantine: {len(ext.quarantine_findings)} finding(s)")
            for f in ext.quarantine_findings[:5]:
                print(f"    - [{f['category']}] {f['source']}: {f['pattern']}")
        for r in ext.reasons:
            print(f"reason    : {r}")
    return 0 if ext.admitted else 1


def cmd_guard(args: argparse.Namespace) -> int:
    """Fast pre-action check for editor/agent hooks: allow/deny a single proposed
    file path and/or shell command against the repo's contract.

    Reads from --path/--command, or from a Claude Code hook JSON payload on stdin
    (tool_input.file_path / tool_input.command). With --hook-output, emits Claude
    Code's PreToolUse decision JSON and always exits 0 (the JSON carries the deny)."""
    path = args.path
    command = args.command
    if args.stdin_json:
        try:
            payload = json.loads(sys.stdin.read() or "{}")
        except (json.JSONDecodeError, ValueError):
            payload = {}
        ti = payload.get("tool_input") or {}
        path = path or ti.get("file_path") or ti.get("path") or ti.get("notebook_path")
        command = command or ti.get("command")

    decision = guard(repo_path=args.repo, path=path, command=command)

    if args.hook_output:
        # Claude Code PreToolUse hook format. "deny" blocks the tool call; on
        # allow we stay silent (exit 0, no decision) so normal flow continues.
        if decision.allowed:
            print("{}")
        else:
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"Umbra: {decision.reason}",
                }
            }))
        return 0

    if args.json:
        _print(decision.to_public(), True)
    else:
        print(("ALLOW" if decision.allowed else "DENY") + f"  {decision.reason}")
    return 0 if decision.allowed else 1


# A commented starter contract written by `umbra init`. Conservative by default:
# dependency-manifest scope, small diff budget, deploy/CI/secrets off-limits.
_STARTER_CONTRACT = """# Umbra executable change contract — the machine-enforced boundary for agent work.
# Docs: https://github.com/bkd-dotcom/umbra-umbrella  ·  edited by humans, versioned in git.
version: 2
task_type: dependency-remediation

# Allowlist: when set, a change touching anything outside these globs is a violation.
allowed_paths:
  - "package.json"
  - "package-lock.json"
  - "requirements.txt"
  - "src/**"

# Always-forbidden, even if inside allowed_paths (fail-closed, case-insensitive).
forbidden_paths:
  - ".github/workflows/**"
  - "infra/**"
  - "deploy/**"
  - "**/*secret*"
  - "**/.env*"

# Diff budget + the checks a change must pass to earn branch-PR (L2) authority.
max_files_changed: 5
required_checks:
  - "npm test"

# Capability graph (v2, optional). Uncomment to restrict tools / bash / MCP / skills.
# allowed_tools:  [Read, Edit, Bash]
# denied_bash:    ["docker\\\\s+run", "kubectl"]
# allowed_mcp:    ["github:search"]
# allowed_skills: ["web-search"]

# Change-control provenance (surfaced honestly in the receipt).
policy_owner: your-team
policy_version: "1.0"
"""


def cmd_init(args: argparse.Namespace) -> int:
    """Scaffold a starter ``.umbra/admission.yaml`` in a repo so a new user is one
    command away from a governed change. Never overwrites without ``--force``."""
    root = Path(args.repo).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    dest = root / ".umbra" / "admission.yaml"
    if dest.exists() and not args.force:
        print(f"error: {dest} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(_STARTER_CONTRACT)
    print(f"wrote {dest}")
    print("Next: edit the scope, then run  umbra admit .  (or add the GitHub Action).")
    return 0


# Static shell-completion scripts. Kept simple + dependency-free (no argcomplete):
# they complete the subcommand names, which is the high-value case.
_COMMANDS = "admit verify brake provenance gates comment admit-extension guard init completion"
_COMPLETIONS = {
    "bash": f"""# umbra bash completion — add to ~/.bashrc:  eval "$(umbra completion bash)"
_umbra_complete() {{
  local cur="${{COMP_WORDS[COMP_CWORD]}}"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "{_COMMANDS}" -- "$cur") )
  fi
}}
complete -o default -F _umbra_complete umbra
""",
    "zsh": f"""# umbra zsh completion — add to ~/.zshrc:  eval "$(umbra completion zsh)"
_umbra() {{
  local -a cmds
  cmds=({_COMMANDS})
  if (( CURRENT == 2 )); then
    compadd -- $cmds
  else
    _files
  fi
}}
compdef _umbra umbra
""",
    "fish": f"""# umbra fish completion — save to ~/.config/fish/completions/umbra.fish
complete -c umbra -n "__fish_use_subcommand" -a "{_COMMANDS}"
""",
}


def cmd_completion(args: argparse.Namespace) -> int:
    """Print a shell completion script for bash / zsh / fish."""
    script = _COMPLETIONS.get(args.shell)
    if not script:
        print(f"error: unsupported shell {args.shell!r}", file=sys.stderr)
        return 2
    print(script)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="umbra", description="Agent-agnostic change-control plane for coding agents.")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_admit = sub.add_parser("admit", help="Run the admission pipeline: govern an agent's change to a repo.")
    p_admit.add_argument("repo", help="Path to a git checkout to run the agent in.")
    p_admit.add_argument("--mission", required=True, help="The bounded task handed to the agent.")
    p_admit.add_argument("--agent", help="Force a specific agent (e.g. codex-cli, claude-code, or any registered executor).")
    p_admit.add_argument("--prefer", help="Comma-separated preference order when auto-selecting (e.g. 'claude-code,codex-cli').")
    p_admit.add_argument("--label", help="Repo label for the receipt (defaults to the directory name).")
    p_admit.add_argument("--owner", default="local", help="Owner key for the passport store.")
    p_admit.add_argument("--store", help="Path to a JSON passport store to persist the earned authority.")
    p_admit.add_argument("--receipt-out", help="Write the signed receipt envelope to this file.")
    p_admit.add_argument("--min-authority", type=int, default=2, help="Exit non-zero unless the run earns at least this level (default 2 = branch-PR).")
    p_admit.set_defaults(func=cmd_admit)

    p_scan = sub.add_parser("scan", help="Layered SAST over a repo (deterministic floor + optional Semgrep): find code vulnerabilities.")
    p_scan.add_argument("repo", help="Path to a checkout OR a git URL (shallow-cloned to a disposable temp dir).")
    p_scan.add_argument("--semgrep", action="store_true", help="Also run Semgrep if installed (merged & deduped; absence is non-fatal).")
    p_scan.add_argument("--semgrep-config", default="auto", help="Semgrep config/ruleset (default 'auto'; pass a local path for offline).")
    p_scan.add_argument("--treesitter", action="store_true", help="Also run the tree-sitter AST layer if the optional packages are installed (higher-precision multi-language; non-fatal if absent).")
    p_scan.add_argument("--sarif", action="store_true", help="Emit SARIF 2.1.0 (GitHub code-scanning standard).")
    p_scan.add_argument("--output", "-o", help="Write output to this file instead of stdout.")
    p_scan.add_argument("--depth", type=int, default=1, help="Clone depth when scanning a git URL (default 1).")
    p_scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"], help="Exit non-zero if any finding meets/exceeds this severity (gate CI).")
    p_scan.add_argument("--fix", action="store_true", help="Propose a governed, receipt-sealed fix per finding: bounded mission → admission pipeline → earned authority (never merges).")
    p_scan.add_argument("--fix-agent", help="Executor that drafts fixes with --fix (e.g. codex-cli, claude-code). Default: auto-select a live agent, else deterministic (no change).")
    p_scan.add_argument("--max-fixes", type=int, default=10, help="Max findings to propose fixes for with --fix (highest severity first; default 10).")
    p_scan.set_defaults(func=cmd_scan)

    p_verify = sub.add_parser("verify", help="Verify a signed receipt against a pinned public key.")
    p_verify.add_argument("receipt", help="Path to a receipt envelope JSON file.")
    p_verify.add_argument("--public-key", help="Base64 Ed25519 public key to verify against (defaults to this instance's key).")
    p_verify.set_defaults(func=cmd_verify)

    p_brake = sub.add_parser("brake", help="Emergency Brake: revoke a repo's earned authority to Level 0.")
    p_brake.add_argument("owner", help="Owner key.")
    p_brake.add_argument("repo", help="Repo label.")
    p_brake.add_argument("--store", required=True, help="Path to the JSON passport store.")
    p_brake.add_argument("--reason", help="Reason recorded with the revocation.")
    p_brake.set_defaults(func=cmd_brake)

    p_prov = sub.add_parser("provenance", help="Emit an in-toto/SLSA provenance statement for a receipt.")
    p_prov.add_argument("receipt", help="Path to a receipt envelope JSON file.")
    p_prov.set_defaults(func=cmd_provenance)

    p_gates = sub.add_parser("gates", help="Print the G1/G2/G3 proof-gate summary for a receipt (exit non-zero unless all pass).")
    p_gates.add_argument("receipt", help="Path to a receipt envelope JSON file.")
    p_gates.add_argument("--json", action="store_true", help="Emit the gate summary as JSON.")
    p_gates.set_defaults(func=cmd_gates)

    p_comment = sub.add_parser("comment", help="Render the canonical PR-comment markdown from an 'admit --json' payload.")
    p_comment.add_argument("report", nargs="?", default="-", help="Path to the {report, receipt} JSON (default: stdin).")
    p_comment.set_defaults(func=cmd_comment)

    p_ext = sub.add_parser("admit-extension", help="Govern an agent skill / MCP extension: fingerprint bytes, quarantine docs, admit or deny.")
    p_ext.add_argument("path", help="Path to the extension directory (skill dir or MCP server).")
    p_ext.add_argument("--kind", choices=["skill", "mcp"], help="Force the extension kind (default: auto-detect).")
    p_ext.add_argument("--repo", help="Repo checkout whose .umbra/admission.yaml supplies the allowed_skills/allowed_mcp allowlist.")
    p_ext.add_argument("--allow-quarantined", action="store_true", help="Admit even if documentation carries manipulation findings (explicit human override).")
    p_ext.add_argument("--asbom", action="store_true", help="Emit a CycloneDX-aligned ASBOM for the extension instead of the verdict.")
    p_ext.add_argument("--org", help="Org name to stamp on the ASBOM metadata.")
    p_ext.set_defaults(func=cmd_admit_extension)

    p_guard = sub.add_parser("guard", help="Fast pre-action check for editor/agent hooks: allow/deny one file path or command against the contract.")
    p_guard.add_argument("--repo", default=".", help="Repo checkout to load the contract from (default: current dir).")
    p_guard.add_argument("--path", help="A proposed file path the agent is about to write/edit.")
    p_guard.add_argument("--command", help="A proposed shell command the agent is about to run.")
    p_guard.add_argument("--stdin-json", action="store_true", help="Read a Claude Code hook JSON payload from stdin (tool_input.file_path / .command).")
    p_guard.add_argument("--hook-output", action="store_true", help="Emit Claude Code PreToolUse decision JSON (deny blocks; exit 0).")
    p_guard.set_defaults(func=cmd_guard)

    p_init = sub.add_parser("init", help="Scaffold a starter .umbra/admission.yaml in a repo.")
    p_init.add_argument("repo", nargs="?", default=".", help="Repo directory to write into (default: current dir).")
    p_init.add_argument("--force", action="store_true", help="Overwrite an existing .umbra/admission.yaml.")
    p_init.set_defaults(func=cmd_init)

    p_comp = sub.add_parser("completion", help="Print a shell completion script (bash | zsh | fish).")
    p_comp.add_argument("shell", choices=["bash", "zsh", "fish"], help="Shell to emit completion for.")
    p_comp.set_defaults(func=cmd_completion)

    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Thread the top-level --json down to subcommands.
    if not hasattr(args, "json"):
        args.json = False
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
