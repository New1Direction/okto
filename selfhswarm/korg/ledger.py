"""
korg-ledger@v1 canonicalization, hash chain, and verification.

Implements the frozen Korg spec (``korg/spec/korg-ledger-v1/SPEC.md``):

- canonical bytes = JSON with sorted keys, ``,``/``:`` separators, non-ASCII
  ``\\uXXXX``-escaped (pure ASCII output);
- ``entry_hash`` = SHA-256 (or HMAC-SHA256 with a key) of the canonical event
  minus ``entry_hash``/``event_sig``; ``prev_hash`` links to the previous
  event, ``"0" * 64`` for the first.

Okto is stricter than the spec on numbers: floats are rejected outright
because the Korg JS verifier cannot hash them (SPEC §7).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

SPEC_VERSION = "korg-ledger@v1"
GENESIS_HASH = "0" * 64
HASH_FIELDS = ("entry_hash", "event_sig")
_SAFE_INT_MAX = 2**53 - 1


def _check_number_domain(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > _SAFE_INT_MAX:
            raise ValueError(f"{path}: integer outside ±(2^53-1)")
        return
    if isinstance(value, float):
        raise ValueError(f"{path}: floats are not canonicalizable in korg-ledger@v1")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(f"{path}: non-string object key")
            _check_number_domain(v, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _check_number_domain(v, f"{path}[{i}]")
        return
    raise ValueError(f"{path}: unsupported JSON type {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Canonical korg-ledger@v1 bytes for *value*."""
    _check_number_domain(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def chain_hash(event: dict, key: bytes | None = None) -> str:
    preimage = canonicalize({k: v for k, v in event.items() if k not in HASH_FIELDS})
    if key is not None:
        return hmac.new(key, preimage, hashlib.sha256).hexdigest()
    return hashlib.sha256(preimage).hexdigest()


def seal_chain(events: list[dict], key: bytes | None = None) -> list[dict]:
    """Set ``prev_hash``/``entry_hash`` on *events* in order (mutates and returns them)."""
    prev = GENESIS_HASH
    for event in events:
        event.pop("entry_hash", None)
        event["prev_hash"] = prev
        event["entry_hash"] = chain_hash(event, key)
        prev = event["entry_hash"]
    return events


def verify_chain(events: list, key: bytes | None = None) -> list[str]:
    """Empty list iff the chain is intact. Each error names a ``seq_id``."""
    errors: list[str] = []
    expected_prev: str | None = GENESIS_HASH
    for idx, e in enumerate(events):
        if not isinstance(e, dict):
            errors.append(f"event {idx} is not a JSON object")
            expected_prev = None
            continue
        sid = e.get("seq_id")
        stored = e.get("entry_hash")
        if stored is None:
            errors.append(f"seq {sid}: missing entry_hash")
            expected_prev = None
            continue
        if e.get("prev_hash") != expected_prev:
            errors.append(f"seq {sid}: prev_hash breaks the chain")
        try:
            computed = chain_hash(e, key)
        except ValueError as exc:
            errors.append(f"seq {sid}: not canonicalizable ({exc})")
        else:
            if computed != stored:
                errors.append(f"seq {sid}: entry_hash mismatch (content tampered)")
        expected_prev = stored
    return errors


def verify_dag(events: list) -> list[str]:
    """
    Causal checks for JournalEvent records: contiguous ``seq_id`` from 1,
    ``metadata.triggered_by`` strictly earlier, ``causation_id`` naming the
    parent's ``event_id``, and exactly one root.

    Korg's reference ``verify_dag`` reads ``triggered_by`` at the top level
    only, so nested JournalEvents get just the uniqueness check there; this
    walks the nested field too.
    """
    errors: list[str] = []
    event_ids: dict[int, str] = {}
    roots = 0
    for pos, e in enumerate(events, start=1):
        if not isinstance(e, dict):
            continue
        sid = e.get("seq_id")
        if sid != pos:
            errors.append(f"seq {sid}: expected seq_id {pos}")
        meta = e.get("metadata") if isinstance(e.get("metadata"), dict) else {}
        tb = meta.get("triggered_by")
        if tb is None:
            roots += 1
            if meta.get("causation_id") is not None:
                errors.append(f"seq {sid}: root event carries a causation_id")
        elif not isinstance(tb, int) or isinstance(tb, bool):
            errors.append(f"seq {sid}: triggered_by {tb!r} is not a seq_id")
        elif isinstance(sid, int) and tb >= sid:
            errors.append(f"seq {sid}: triggered_by {tb} is not strictly earlier")
        elif tb not in event_ids:
            errors.append(f"seq {sid}: triggered_by {tb} does not exist")
        elif meta.get("causation_id") != event_ids[tb]:
            errors.append(f"seq {sid}: causation_id does not match seq {tb} event_id")
        if isinstance(sid, int):
            event_ids[sid] = meta.get("event_id")
    if events and roots != 1:
        errors.append(f"expected exactly one root event, found {roots}")
    return errors
