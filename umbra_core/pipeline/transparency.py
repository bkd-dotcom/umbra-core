"""Append-only Merkle transparency log for receipts.

A signed receipt proves "Umbra issued this specific record". A transparency log
proves something the signature alone cannot: that a receipt was **entered into an
append-only history** and that history has **not been rewritten** since. This is
the difference between "this document is authentic" and "this document can't have
been quietly replaced or back-dated".

Design (RFC 6962-style, dependency-free):
- Each entry stores the receipt's canonical hash and a leaf hash
  ``H(0x00 || canonical_hash)``.
- The log root is the Merkle root over all leaf hashes (``H(0x01 || left || right)``
  for interior nodes). Appending an entry advances the root deterministically.
- An **inclusion proof** lets anyone recompute the root from a single leaf + a
  small set of sibling hashes, proving the entry is in the tree without the whole
  log.
- A **consistency check** verifies a newer log is an append-only extension of an
  older one (no history was rewritten) by re-deriving the old root's leaves.

Storage is pluggable via :class:`LogStore` (in-memory + JSON-file provided). The
tree math is stateless and testable on its own.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leaf_hash(canonical_hash: str) -> str:
    """RFC 6962 leaf hash: H(0x00 || data)."""
    return _h(_LEAF_PREFIX + canonical_hash.encode("utf-8"))


def _node_hash(left: str, right: str) -> str:
    return _h(_NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right))


def merkle_root(leaves: list[str]) -> str:
    """Merkle root over ``leaves`` (already hashed). Empty tree → H(b"")."""
    if not leaves:
        return _h(b"")
    level = list(leaves)
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # odd node promoted
        level = nxt
    return level[0]


def inclusion_proof(leaves: list[str], index: int) -> list[dict[str, str]]:
    """Sibling hashes proving ``leaves[index]`` is in the tree, bottom-up.

    Each step is ``{"hash": <sibling>, "side": "left"|"right"}`` describing where
    the sibling sits relative to the running hash.
    """
    if not (0 <= index < len(leaves)):
        raise IndexError("leaf index out of range")
    proof: list[dict[str, str]] = []
    level = list(leaves)
    idx = index
    while len(level) > 1:
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                if i == idx:
                    proof.append({"hash": level[i + 1], "side": "right"})
                elif i + 1 == idx:
                    proof.append({"hash": level[i], "side": "left"})
                nxt.append(_node_hash(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # odd promoted; no sibling recorded
        idx //= 2
        level = nxt
    return proof


def verify_inclusion(leaf: str, index: int, proof: list[dict[str, str]], root: str) -> bool:
    """Recompute the root from a leaf + inclusion proof and compare to ``root``."""
    running = leaf
    for step in proof:
        sibling = step["hash"]
        if step["side"] == "right":
            running = _node_hash(running, sibling)
        else:
            running = _node_hash(sibling, running)
    return running == root


@dataclass
class LogEntry:
    index: int
    canonical_hash: str
    leaf: str
    logged_at: str
    receipt_repo: str | None = None
    authority_level: int | None = None

    def to_public(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "canonical_hash": self.canonical_hash,
            "leaf": self.leaf,
            "logged_at": self.logged_at,
            "receipt_repo": self.receipt_repo,
            "authority_level": self.authority_level,
        }


@runtime_checkable
class LogStore(Protocol):
    def append(self, entry: dict[str, Any]) -> None: ...
    def all(self) -> list[dict[str, Any]]: ...


class InMemoryLogStore:
    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def append(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self._entries.append(dict(entry))

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(e) for e in self._entries]


class JsonFileLogStore:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    def append(self, entry: dict[str, Any]) -> None:
        with self._lock:
            data = self._read()
            data.append(dict(entry))
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(data, indent=2, default=str))

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._read()

    def _read(self) -> list[dict[str, Any]]:
        try:
            return json.loads(self._path.read_text())
        except (OSError, json.JSONDecodeError):
            return []


class TransparencyLog:
    """An append-only, Merkle-rooted log of receipt hashes."""

    def __init__(self, store: LogStore | None = None) -> None:
        self.store = store or InMemoryLogStore()

    def _leaves(self) -> list[str]:
        return [e["leaf"] for e in self.store.all()]

    def append_receipt(self, envelope: dict[str, Any]) -> dict[str, Any]:
        """Append a signed receipt envelope; return its entry + inclusion proof + new root."""
        canonical_hash = envelope.get("canonical_hash")
        if not canonical_hash:
            raise ValueError("Envelope has no canonical_hash to log.")
        receipt = envelope.get("receipt") or {}
        existing = self.store.all()
        index = len(existing)
        entry = LogEntry(
            index=index,
            canonical_hash=canonical_hash,
            leaf=leaf_hash(canonical_hash),
            logged_at=datetime.now(UTC).isoformat(),
            receipt_repo=receipt.get("repo"),
            authority_level=receipt.get("authority_level"),
        )
        self.store.append(entry.to_public())
        leaves = self._leaves()
        return {
            "entry": entry.to_public(),
            "root": merkle_root(leaves),
            "size": len(leaves),
            "inclusion_proof": inclusion_proof(leaves, index),
        }

    def root(self) -> str:
        return merkle_root(self._leaves())

    def size(self) -> int:
        return len(self.store.all())

    def prove_inclusion(self, index: int) -> dict[str, Any]:
        leaves = self._leaves()
        return {
            "leaf": leaves[index],
            "index": index,
            "proof": inclusion_proof(leaves, index),
            "root": merkle_root(leaves),
            "size": len(leaves),
        }

    def verify_appended_since(self, old_root: str, old_size: int) -> bool:
        """Verify the log is an append-only extension of an earlier ``(root, size)``.

        Re-derives the Merkle root over the first ``old_size`` current leaves and
        checks it equals ``old_root`` — i.e. the historical prefix is unchanged and
        the log only grew. A rewrite of any old entry changes the prefix root and
        fails this check.
        """
        leaves = self._leaves()
        if old_size > len(leaves):
            return False
        if old_size == 0:
            return True
        return merkle_root(leaves[:old_size]) == old_root
