"""Executable Change Contract — the machine-enforced boundary for agent work.

``.umbra/nightshift.md`` is prose guidance for the agent. This module adds the
*enforced* half: a machine-readable ``.umbra/admission.yaml`` that declares what
a change is allowed to touch, and a deterministic evaluator that checks a real
changeset against it — **outside the model**. A prompt is not a control; this is.

The contract answers, before any PR is opened:

    "Was this change permitted to touch these files, at this size, given this
     repository's policy?"

Design invariants:
- Fully deterministic and offline: no model, no network, no Codex. The same
  changeset + contract always yields the same verdict.
- Fail-closed on scope: an explicit ``forbidden_paths`` match is always a
  violation; ``allowed_paths`` (when set) is an allowlist — anything outside it
  is a violation.
- Safe default: when a repo ships no ``.umbra/admission.yaml``, a conservative
  default contract applies (dependency-manifest scope, small diff budget) so the
  feature is meaningful even without per-repo configuration.
- Never widens authority: the contract can only *restrict* what Umbra does. It
  never grants auto-merge or any authority the rest of the system doesn't already
  gate behind a human.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Where a repo declares its executable contract (sits beside the prose policy).
CONTRACT_REL = ".umbra/admission.yaml"
_CONTRACT_MAX_BYTES = 16_000

# A conservative default when a repo ships no admission.yaml. Dependency-manifest
# scope only, small diff budget, tests requested, deployment/CI/auth off-limits —
# the same posture the prose nightshift policy describes, made enforceable.
_DEFAULT_CONTRACT: dict[str, Any] = {
    "version": 1,
    "task_type": "dependency-remediation",
    "allowed_paths": [
        "package.json",
        "package-lock.json",
        "requirements.txt",
        "poetry.lock",
        "yarn.lock",
        "pnpm-lock.yaml",
    ],
    "forbidden_paths": [
        ".github/workflows/**",
        "infra/**",
        "deploy/**",
        "**/deploy.yml",
        "**/deploy.yaml",
        "src/auth/**",
        "**/auth/**",
        "**/*secret*",
        "**/.env*",
    ],
    "max_files_changed": 3,
    "required_checks": ["npm test"],
    "network": "deny",
    "authority_on_success": "branch_pr_only",
}


@dataclass(frozen=True)
class Contract:
    """A parsed, enforceable change contract."""

    version: int = 1
    task_type: str = "dependency-remediation"
    allowed_paths: tuple[str, ...] = ()
    forbidden_paths: tuple[str, ...] = ()
    max_files_changed: int = 0  # 0 = unbounded
    required_checks: tuple[str, ...] = ()
    network: str = "deny"
    authority_on_success: str = "branch_pr_only"
    source: str = "default"  # "repo" when loaded from .umbra/admission.yaml, else "default"
    # Policy ownership / change-control provenance. Optional in the file; absent →
    # the policy is treated as UNSIGNED (fail-safe: surfaced, never silently trusted).
    policy_owner: str = ""
    policy_version: str = ""
    policy_approved_at: str = ""

    def to_public(self) -> dict[str, Any]:
        """Serializable view for API responses / receipts."""
        return {
            "version": self.version,
            "task_type": self.task_type,
            "allowed_paths": list(self.allowed_paths),
            "forbidden_paths": list(self.forbidden_paths),
            "max_files_changed": self.max_files_changed,
            "required_checks": list(self.required_checks),
            "network": self.network,
            "authority_on_success": self.authority_on_success,
            "source": self.source,
            "policy_owner": self.policy_owner,
            "policy_version": self.policy_version,
            "policy_approved_at": self.policy_approved_at,
            "policy_status": self.policy_status(),
        }

    def policy_status(self) -> dict[str, Any]:
        """Human-owned change-control status of this policy.

        A contract hash proves *which* rules ran; this states *who authorized* them.
        Honest wording: declared owner/version metadata is NOT a cryptographic
        signature, so we never call metadata "signed". Fail-safe default is
        ``incomplete``. Values:
          - ``declared``               — a human owner AND version are declared (change-
                                         controlled metadata, but not cryptographically proven).
          - ``incomplete``             — owner or version missing (default posture).
          - ``cryptographically-signed`` — reserved for a policy carrying a verifiable
                                         signature; not asserted here (no policy-signature
                                         scheme is verified yet), stated so the field is honest.
        Expiry/approval timestamps are advisory metadata surfaced for review; they do
        not by themselves widen authority (authority is still gated by the deterministic
        contract + verifier + checks).
        """
        declared = bool(self.policy_owner and self.policy_version)
        status = "declared" if declared else "incomplete"
        return {
            "status": status,
            "owner": self.policy_owner or None,
            "version": self.policy_version or None,
            "approved_at": self.policy_approved_at or None,
            "note": (
                "Policy declares a human owner and version (change-controlled metadata). "
                "This is declared provenance, not a cryptographic signature."
                if declared else
                "Policy metadata is incomplete (no declared owner/version). Authority still "
                "requires the deterministic contract, independent verifier, and required "
                "checks; production teams should own and version the policy."
            ),
        }

    def hash(self) -> str:
        """Stable content hash of the contract — binds a receipt to the exact
        rules that applied. Excludes provenance (``source`` and policy ownership/
        version/approval + derived ``policy_status``), which describe *who* authored
        the rules, not the rules themselves — so the rules-hash stays stable while
        policy identity is bound separately via the signed receipt payload."""
        _provenance = {"source", "policy_owner", "policy_version", "policy_approved_at", "policy_status"}
        payload = {k: v for k, v in self.to_public().items() if k not in _provenance}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class ContractCheck:
    name: str
    passed: bool
    detail: str


@dataclass
class ContractResult:
    """The verdict of evaluating a changeset against a contract."""

    status: str  # "pass" | "violated"
    checks: list[ContractCheck] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    contract_hash: str = ""

    @property
    def passed(self) -> bool:
        return self.status == "pass"

    def to_public(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "passed": self.passed,
            "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail} for c in self.checks],
            "violations": list(self.violations),
            "changed_files": list(self.changed_files),
            "contract_hash": self.contract_hash,
        }


# --- Minimal, dependency-free parser for the constrained schema -------------
# admission.yaml is a small, flat document: scalar keys plus simple "- item"
# lists. We parse exactly that shape without requiring PyYAML (an undeclared
# transitive dep). If PyYAML is present we prefer it for robustness.
def _parse_admission_text(text: str) -> dict[str, Any]:
    try:  # Prefer a real YAML parser when available.
        import yaml  # type: ignore

        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 - fall back to the tolerant mini-parser
        return _mini_yaml(text)


def _coerce(scalar: str) -> Any:
    s = scalar.strip().strip('"').strip("'")
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if s.lower() in {"true", "false"}:
        return s.lower() == "true"
    return s


def _mini_yaml(text: str) -> dict[str, Any]:
    """Parse the constrained admission schema: top-level ``key: value`` and
    ``key:`` followed by indented ``- item`` list entries. Ignores comments and
    anything it doesn't understand (fail-open to defaults, never crash)."""
    data: dict[str, Any] = {}
    current_key: str | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        list_item = re.match(r"^\s*-\s+(.*)$", line)
        if list_item and current_key is not None:
            data.setdefault(current_key, [])
            if isinstance(data[current_key], list):
                data[current_key].append(_coerce(list_item.group(1)))
            continue
        kv = re.match(r"^([A-Za-z0-9_]+)\s*:\s*(.*)$", line)
        if kv:
            key, value = kv.group(1), kv.group(2).strip()
            current_key = key
            if value == "":
                data[key] = []  # a list or block follows
            else:
                data[key] = _coerce(value)
    return data


def _as_str_item(v: Any) -> str:
    # The mini-YAML parser coerces bare ``true``/``false`` to Python bools; a
    # required-check like ``- true`` must round-trip to the lowercase string
    # ``"true"`` (an allowlisted eval profile), not ``"True"``.
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v).strip()


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(s for s in (_as_str_item(v) for v in value) if s)
    if isinstance(value, str) and value.strip():
        return (value.strip(),)
    return ()


def contract_from_dict(data: dict[str, Any], source: str = "repo") -> Contract:
    """Build a Contract from a parsed dict, falling back to defaults per-field."""
    d = data or {}
    return Contract(
        version=int(d.get("version", 1)) if str(d.get("version", "1")).lstrip("-").isdigit() else 1,
        task_type=str(d.get("task_type", _DEFAULT_CONTRACT["task_type"])),
        allowed_paths=_as_str_tuple(d.get("allowed_paths")) or (),
        forbidden_paths=_as_str_tuple(d.get("forbidden_paths")) or (),
        max_files_changed=int(d["max_files_changed"]) if str(d.get("max_files_changed", "")).lstrip("-").isdigit() else 0,
        required_checks=_as_str_tuple(d.get("required_checks")),
        network=str(d.get("network", "deny")).lower(),
        authority_on_success=str(d.get("authority_on_success", "branch_pr_only")),
        source=source,
        policy_owner=str(d.get("policy_owner", "")).strip(),
        policy_version=str(d.get("policy_version", "")).strip(),
        policy_approved_at=str(d.get("policy_approved_at", "")).strip(),
    )


def default_contract() -> Contract:
    return contract_from_dict(_DEFAULT_CONTRACT, source="default")


def load_contract(repo_path: Path | str | None) -> Contract:
    """Load ``.umbra/admission.yaml`` from a checkout, else the default contract.

    Never raises: a malformed or missing file yields the safe default so the
    admission machinery always has an enforceable contract to work with."""
    if repo_path is None:
        return default_contract()
    try:
        path = Path(repo_path) / ".umbra" / "admission.yaml"
        if path.is_file():
            text = path.read_text(errors="replace")[:_CONTRACT_MAX_BYTES]
            parsed = _parse_admission_text(text)
            contract = contract_from_dict(parsed, source="repo")
            # A repo file with no usable scope rules is treated as "present but
            # empty" — merge the default scope so it still enforces something.
            if not contract.allowed_paths and not contract.forbidden_paths:
                base = default_contract()
                return Contract(
                    version=contract.version,
                    task_type=contract.task_type or base.task_type,
                    allowed_paths=base.allowed_paths,
                    forbidden_paths=base.forbidden_paths,
                    max_files_changed=contract.max_files_changed or base.max_files_changed,
                    required_checks=contract.required_checks or base.required_checks,
                    network=contract.network,
                    authority_on_success=contract.authority_on_success,
                    source="repo",
                    policy_owner=contract.policy_owner,
                    policy_version=contract.policy_version,
                    policy_approved_at=contract.policy_approved_at,
                )
            return contract
    except OSError:
        pass
    return default_contract()


def _strip_dot_slash(s: str) -> str:
    """Remove a single leading ``./`` (not arbitrary leading dots — ``.env`` must
    stay ``.env``)."""
    return s[2:] if s.startswith("./") else s


def is_malformed_path(path: str) -> bool:
    """A changed-file path we refuse to reason about (and treat as a violation).

    Git output that has been quoted/escaped (non-ASCII under the default
    ``core.quotePath``), or that contains traversal/absolute/NUL/backslash
    components, cannot be matched reliably against globs — a permissive miss
    would be a scope bypass. We fail closed on these. (Umbra reads git paths with
    ``core.quotePath=false`` so legitimate non-ASCII names arrive unquoted; a path
    that still looks quoted here is anomalous.)
    """
    if not path:
        return True
    if "\x00" in path or "\\" in path:
        return True
    if path.startswith('"') and path.endswith('"'):
        return True  # git-quoted (quotePath) form leaked through
    if path.startswith("/"):
        return True  # absolute
    segments = _strip_dot_slash(path).split("/")
    if any(seg == ".." for seg in segments):
        return True  # traversal
    return False


def _matches_any(path: str, patterns: tuple[str, ...], *, case_insensitive: bool = False) -> bool:
    """Glob match with ``**`` support. ``fnmatch`` treats ``*`` as crossing ``/``
    so ``dir/**`` works; we also try matching the basename for bare patterns and
    for ``**/name`` patterns so a root-level file like ``.env`` still matches
    ``**/.env*``.

    ``case_insensitive`` is used for ``forbidden_paths`` so that a case-insensitive
    filesystem (macOS/APFS, Windows/NTFS) cannot be used to bypass a forbidden
    glob by capitalizing a letter (``Deploy.yml`` vs ``deploy.yml``).
    """
    def _fold(s: str) -> str:
        return s.casefold() if case_insensitive else s

    norm = _fold(_strip_dot_slash(path))
    base = norm.rsplit("/", 1)[-1]
    for pat in patterns:
        p = _fold(_strip_dot_slash(pat))
        if fnmatch.fnmatchcase(norm, p):
            return True
        # Allow "dir/**" to match "dir/x" and "dir/x/y".
        if p.endswith("/**") and (norm == p[:-3] or norm.startswith(p[:-2])):
            return True
        # Allow a bare filename pattern to match at any depth.
        if "/" not in p and fnmatch.fnmatchcase(base, p):
            return True
        # Allow "**/name" (or "**/name*") to match the basename at any depth,
        # including root level (where the "**/" prefix would otherwise require
        # at least one leading directory segment).
        if p.startswith("**/") and fnmatch.fnmatchcase(base, p[3:]):
            return True
    return False


def evaluate_contract(changed_files: list[str], contract: Contract) -> ContractResult:
    """Deterministically check a changeset against a contract.

    Rules, in order of severity:
      1. Any changed file matching ``forbidden_paths`` → violation (fail-closed).
      2. When ``allowed_paths`` is set, any changed file NOT matching it →
         violation (it's an allowlist).
      3. More changed files than ``max_files_changed`` (when > 0) → violation.

    ``required_checks`` and ``network`` are recorded on the contract but verified
    by the independent verifier (they concern execution, not the changeset shape)."""
    files = [f for f in (changed_files or []) if f]
    checks: list[ContractCheck] = []
    violations: list[str] = []

    # 0. Malformed / unmatchable paths — fail closed. A quoted/escaped, absolute,
    #    or traversal path can't be matched reliably against globs, so we treat it
    #    as a violation rather than risk a permissive miss (scope bypass).
    malformed = [f for f in files if is_malformed_path(f)]
    if malformed:
        for f in malformed:
            violations.append(f"Refused an unmatchable/malformed path (fail-closed): {f!r}")
    checks.append(ContractCheck(
        "path_wellformed",
        not malformed,
        "All changed paths are well-formed." if not malformed
        else f"{len(malformed)} malformed/unmatchable path(s) refused: {', '.join(repr(m) for m in malformed)}",
    ))

    # 1. Forbidden paths — always a violation. Matched CASE-INSENSITIVELY so a
    #    case-insensitive filesystem can't bypass a forbidden glob via capitalization.
    forbidden_hits = [f for f in files if _matches_any(f, contract.forbidden_paths, case_insensitive=True)]
    if forbidden_hits:
        for hit in forbidden_hits:
            violations.append(f"Changed a forbidden path: {hit}")
    checks.append(ContractCheck(
        "forbidden_paths",
        not forbidden_hits,
        "No forbidden paths touched." if not forbidden_hits else f"Touched {len(forbidden_hits)} forbidden path(s): {', '.join(forbidden_hits)}",
    ))

    # 2. Allowlist — everything must be inside allowed_paths (when set). Matched
    #    case-sensitively (an allowlist is an exact declaration); a malformed path
    #    already failed step 0.
    if contract.allowed_paths:
        outside = [f for f in files if not is_malformed_path(f) and not _matches_any(f, contract.allowed_paths)]
        if outside:
            for f in outside:
                violations.append(f"Changed a file outside the allowed scope: {f}")
        checks.append(ContractCheck(
            "allowed_paths",
            not outside,
            "All changed files are within the allowed scope." if not outside else f"{len(outside)} file(s) outside allowed scope: {', '.join(outside)}",
        ))
    else:
        checks.append(ContractCheck("allowed_paths", True, "No allowlist configured (any path permitted)."))

    # 3. Diff budget.
    if contract.max_files_changed and len(files) > contract.max_files_changed:
        violations.append(f"Changed {len(files)} files, exceeding the max of {contract.max_files_changed}.")
        checks.append(ContractCheck("max_files_changed", False, f"{len(files)} > {contract.max_files_changed} files."))
    else:
        checks.append(ContractCheck(
            "max_files_changed",
            True,
            f"{len(files)} file(s) changed" + (f" (≤ {contract.max_files_changed})" if contract.max_files_changed else " (no limit)") + ".",
        ))

    status = "pass" if not violations else "violated"
    return ContractResult(
        status=status,
        checks=checks,
        violations=violations,
        changed_files=files,
        contract_hash=contract.hash(),
    )
