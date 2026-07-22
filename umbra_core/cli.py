"""The ``umbra`` command-line interface.

One entry point over the agent-agnostic core, so the same governance runs on a
developer's machine, in a git hook, and in CI:

    umbra admit  <repo> --agent claude-code --mission "..."   # govern an agent's change
    umbra verify <receipt.json>                                # verify a signed receipt
    umbra brake  <owner> <repo> --store passports.json         # Emergency Brake -> L0
    umbra provenance <receipt.json>                            # emit SLSA/in-toto statement

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
    issue_passport,
    resolve_available,
    revoke,
    run_admission,
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
                f"(e.g. UMBRA_ENABLE_CLAUDE_CODE=true / UMBRA_ENABLE_CODEX_CLI=true).",
                file=sys.stderr,
            )
            return 2
    else:
        executor = resolve_available(args.prefer.split(",") if args.prefer else None)
        if executor is None:
            print(
                "error: no coding agent is available. Enable one with "
                "UMBRA_ENABLE_CLAUDE_CODE=true or UMBRA_ENABLE_CODEX_CLI=true, "
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
