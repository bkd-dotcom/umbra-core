"""Earned-authority passport — durable, revocable, run-bound authority per repo.

The authority a run *earned* (0 observe / 1 analyze / 2 branch-PR) is not a
setting; it is a fact produced by an admission run. This module makes that fact
durable and enforceable:

- :func:`issue_passport` turns an :class:`AdmissionReport` into a passport bound
  to the exact run (receipt hash, base commit, executor, diff hash, check result)
  with a 7-day expiry. ``auto_merge`` is never stored true.
- :class:`PassportStore` persists passports keyed by ``(owner, repo)``. A default
  in-memory store and a JSON-file store are provided; production supplies its own.
- :func:`gate_pr` is the enforcement point: it refuses a PR when the passport is
  revoked (Emergency Brake), below branch-PR, expired, or absent (in strict mode).
- :func:`revoke` is the Emergency Brake: it forces a repo's authority to Level 0,
  durably, and a PR is then blocked.

The passport can only ever *withhold* authority relative to what a run earned; it
never widens it.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

_DEFAULT_TTL_DAYS = 7


class PassportError(PermissionError):
    """Raised by :func:`gate_pr` when the passport does not permit the action."""

    def __init__(self, message: str, *, reason: str, authority_level: int) -> None:
        super().__init__(message)
        self.reason = reason
        self.authority_level = authority_level


def _now() -> datetime:
    return datetime.now(UTC)


def _key(owner: str, repo: str) -> str:
    return f"{owner}|{repo}"


def issue_passport(report: Any, *, receipt_hash: str | None = None, ttl_days: int = _DEFAULT_TTL_DAYS) -> dict[str, Any]:
    """Build a passport record from an admission report (or its ``to_public`` dict).

    Binds the passport to the exact run so a later PR is traceable to precisely
    this admission. Accepts either an :class:`AdmissionReport` or the dict from
    ``report.to_public()``.
    """
    data = report.to_public() if hasattr(report, "to_public") else dict(report)
    now = _now()
    checks = data.get("checks") or {}
    return {
        "authority_level": int(data.get("authority_level", 0)),
        "authority": data.get("authority", "observe"),
        "authority_label": data.get("authority_label", ""),
        "outcome": data.get("outcome", ""),
        "task_type": data.get("task_type"),
        "contract_hash": (data.get("contract_result") or {}).get("contract_hash"),
        # Tight bindings to the exact admission run.
        "executor": data.get("executor"),
        "base_commit": data.get("base_commit"),
        "diff_hash": data.get("diff_hash"),
        "receipt_hash": receipt_hash,
        "checks_enforcement": checks.get("enforcement"),
        "checks_all_passed": checks.get("all_passed"),
        "admitted_at": now.isoformat(),
        "expires_at": (now + timedelta(days=ttl_days)).isoformat(),
        "revoked": False,
        "revoked_reason": None,
        # Invariant, stored explicitly so it can never be quietly flipped.
        "auto_merge": False,
    }


@runtime_checkable
class PassportStore(Protocol):
    """Storage for earned-authority passports, keyed by ``(owner, repo)``."""

    def save(self, owner: str, repo: str, passport: dict[str, Any]) -> dict[str, Any]: ...
    def get(self, owner: str, repo: str) -> dict[str, Any] | None: ...
    def list(self, owner: str) -> list[dict[str, Any]]: ...


class InMemoryPassportStore:
    """A thread-safe in-process store (default; good for tests and single-process)."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def save(self, owner: str, repo: str, passport: dict[str, Any]) -> dict[str, Any]:
        rec = {**passport, "owner": owner, "repo": repo, "updated_at": _now().isoformat(), "auto_merge": False}
        with self._lock:
            self._data[_key(owner, repo)] = rec
        return rec

    def get(self, owner: str, repo: str) -> dict[str, Any] | None:
        with self._lock:
            rec = self._data.get(_key(owner, repo))
            return dict(rec) if rec else None

    def list(self, owner: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(r) for r in self._data.values() if r.get("owner") == owner]


class JsonFilePassportStore:
    """A durable single-file JSON store (small deployments / local persistence)."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> dict[str, dict[str, Any]]:
        try:
            return json.loads(self._path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, data: dict[str, dict[str, Any]]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(data, indent=2, default=str))

    def save(self, owner: str, repo: str, passport: dict[str, Any]) -> dict[str, Any]:
        rec = {**passport, "owner": owner, "repo": repo, "updated_at": _now().isoformat(), "auto_merge": False}
        with self._lock:
            data = self._read()
            data[_key(owner, repo)] = rec
            self._write(data)
        return rec

    def get(self, owner: str, repo: str) -> dict[str, Any] | None:
        with self._lock:
            return self._read().get(_key(owner, repo))

    def list(self, owner: str) -> list[dict[str, Any]]:
        with self._lock:
            return [r for r in self._read().values() if r.get("owner") == owner]


def revoke(store: PassportStore, owner: str, repo: str, reason: str | None = None) -> dict[str, Any]:
    """Emergency Brake: force a repo's authority to Level 0, durably.

    Creates a revoked record even if the repo never ran admission, so a brake is
    always an explicit, auditable act. A subsequent :func:`gate_pr` will block.
    """
    existing = store.get(owner, repo) or {}
    now = _now()
    revoked = {
        **existing,
        "authority_level": 0,
        "authority": "observe",
        "authority_label": "Observe — authority revoked by Emergency Brake",
        "revoked": True,
        "revoked_reason": reason or "Emergency Brake",
        "revoked_at": now.isoformat(),
        "auto_merge": False,
    }
    return store.save(owner, repo, revoked)


@dataclass
class PassportStatus:
    ok: bool
    authority_level: int
    reason: str
    passport: dict[str, Any] | None


def _is_expired(passport: dict[str, Any]) -> bool:
    exp = passport.get("expires_at")
    if not exp:
        return False
    try:
        return _now() > datetime.fromisoformat(str(exp))
    except ValueError:
        return False


def evaluate(store: PassportStore, owner: str, repo: str, *, require_admission: bool = False) -> PassportStatus:
    """Compute whether the current passport permits a branch-PR, without raising.

    - No passport + ``require_admission`` → not ok (strict mode: no admission, no PR).
    - No passport + not strict            → ok (admission governs only enrolled repos).
    - Revoked / below L2 / expired        → not ok.
    """
    passport = store.get(owner, repo)
    if passport is None:
        if require_admission:
            return PassportStatus(False, 0, "No admission passport for this repository (strict mode requires one).", None)
        return PassportStatus(True, 0, "No passport; admission governs only enrolled repositories.", None)
    if passport.get("revoked"):
        return PassportStatus(False, 0, f"Authority revoked by Emergency Brake: {passport.get('revoked_reason') or 'revoked'}.", passport)
    level = int(passport.get("authority_level", 0))
    if level < 2:
        return PassportStatus(False, level, f"Agent has not earned branch-PR authority (current: {passport.get('authority', 'observe')}). Re-run admission.", passport)
    if _is_expired(passport):
        return PassportStatus(False, level, "The admission passport has expired. Re-run admission.", passport)
    return PassportStatus(True, level, "Branch-PR authority is current.", passport)


def gate_pr(store: PassportStore, owner: str, repo: str, *, require_admission: bool = False) -> dict[str, Any]:
    """Enforcement point: raise :class:`PassportError` unless a branch-PR is permitted.

    Returns the governing passport (or an empty dict when none exists and strict
    mode is off) when the action is allowed.
    """
    status = evaluate(store, owner, repo, require_admission=require_admission)
    if not status.ok:
        raise PassportError(status.reason, reason=status.reason, authority_level=status.authority_level)
    return status.passport or {}
