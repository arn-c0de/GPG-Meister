"""Append-only audit log for security-relevant events.

This is a deliberately separate channel from the diagnostic log (planv2.md §2.11):

- Different sink file, different rotation policy (none).
- Whitelisted event names — anything else is rejected.
- Forbidden keys (the deny-list from §5.4) raise at runtime; the record is dropped
  and a diagnostic entry is recorded instead.
- Optional hash chain: each record carries `prev_hash`, the SHA-256 of the previous
  serialised record, plus a monotonic `seq` counter. A sibling `.tip` file holds
  the hash of the last record.

Threat model — read this before trusting `verify_chain`. The chain is an
*unkeyed* SHA-256 chain. It reliably detects accidental corruption, in-place
edits, record insertion and front/middle truncation (the `seq` counter exposes
gaps and a non-zero start). It does NOT provide cryptographic tamper-evidence
against a same-uid attacker: anyone who can rewrite `audit.log` can recompute
the hashes, renumber `seq`, and overwrite the `.tip` file, since no secret is
involved. Genuine tamper-evidence would require an HMAC keyed by a secret the
attacker cannot read (OS keyring or a root-owned location); that is out of
scope for an unprivileged desktop process. Treat a passing `verify_chain` as
"internally consistent", not "provably authentic".

The log is opened in append mode with mode 0o600 on POSIX. Concurrent writers from
the same process are serialised through an internal lock; hash-chained writes also
take an advisory file lock while scanning and appending.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import sys
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from gpg_meister.storage.atomic_write import atomic_write_bytes
from gpg_meister.storage.file_lock import FileLock
from gpg_meister.storage.permissions import ensure_dir, reject_symlink
from gpg_meister.storage.secret_keys import FORBIDDEN_KEYS, find_secret_violation

_log = logging.getLogger(__name__)

# Whitelisted audit event names. Anything else is rejected.
ALLOWED_EVENTS: Final[frozenset[str]] = frozenset(
    {
        "audit_log_opened",
        "gpg_binary_resolved",
        "gpg_binary_rejected",
        "startup_environment_check",
        "key_generated",
        "key_deleted",
        "key_imported",
        "key_exported_public",
        "key_exported_private",
        "message_signed",
        "message_decrypted",
        "message_decrypt_failed",
        "smartcard_detected",
        "smartcard_keys_synced",
        "smartcard_pin_changed",
        "smartcard_key_moved",
        "smartcard_key_generated",
        "fido_enrolled",
        "fido_derived",
        "key_created_with_token",
        "key_bound_to_token",
        "key_unlocked_with_token",
        "key_unlocked_with_passphrase",
        "key_unlock_forgotten",
        "vault_created",
        "vault_imported",
        "vault_import_failed",
        "config_loaded",
        "config_saved",
    }
)

# The deny-list of sensitive key names lives in `secret_keys` so the audit and
# diagnostic sinks share one source of truth. Re-exported here for callers and
# tests that historically imported it from this module.
__all__ = [
    "FORBIDDEN_KEYS",
    "AuditLog",
    "AuditLogError",
    "emit_best_effort",
    "verify_chain",
]

# Maximum bytes read from the file tail when looking for the last hash chain entry.
# A single audit record is well under 4 KB; 64 KB guarantees we always find one.
_TAIL_CHUNK = 64 * 1024

# Allowed outcome values.
OUTCOME_OK = "ok"
OUTCOME_FAILED = "failed"
OUTCOME_WARNING = "warning"
_VALID_OUTCOMES: Final[frozenset[str]] = frozenset({OUTCOME_OK, OUTCOME_FAILED, OUTCOME_WARNING})


class AuditLogError(Exception):
    """Raised when an audit-log invariant is violated."""


def _utc_now_iso() -> str:
    # No microseconds — second resolution is enough for an audit trail and keeps
    # records compact.
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _actor() -> str:
    if sys.platform != "win32":
        import pwd as _pwd
        try:
            return _pwd.getpwuid(os.geteuid()).pw_name
        except (KeyError, AttributeError):
            return f"uid:{os.geteuid()}"
    return os.environ.get("USERNAME") or "unknown"


_RESERVED_ENVELOPE_KEYS: Final[frozenset[str]] = frozenset(
    {"event", "ts", "actor", "outcome", "prev_hash"}
)


def _check_payload(event: str, payload: Mapping[str, Any]) -> None:
    if event not in ALLOWED_EVENTS:
        raise AuditLogError(f"event {event!r} is not in the audit whitelist")
    violation = find_secret_violation(dict(payload), reserved=_RESERVED_ENVELOPE_KEYS)
    if violation is not None:
        raise AuditLogError(violation)


def _serialise(record: Mapping[str, Any]) -> str:
    """One JSON object per line. Sorted keys for stable hashing."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _open_ro_nofollow(path: Path) -> Any:
    """Open ``path`` read-only, refusing to traverse a final-component symlink."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    return os.fdopen(fd, "rb", closefd=True)


def _seq_after(line: bytes) -> int:
    """Return ``seq + 1`` for a record line, or 0 if it carries no seq."""
    try:
        seq = json.loads(line).get("seq")
    except (json.JSONDecodeError, AttributeError):
        return 0
    if isinstance(seq, int) and seq >= 0:
        return seq + 1
    return 0


class AuditLog:
    """Append-only audit log.

    Construct once per process; pass the instance to anything that needs to emit
    audit events. Closing is optional — the file handle is kept open for the
    lifetime of the process and flushed on every record.
    """

    def __init__(self, path: Path, *, hash_chain: bool = False) -> None:
        self._path = path
        self._tip_path = path.with_name(path.name + ".tip")
        self._hash_chain = hash_chain
        self._lock = threading.Lock()
        self._prev_hash: str | None = None
        # Monotonic record counter; recovered from the tail on reopen. A gap or
        # non-zero start is a tamper signal that survives even without the tip.
        self._seq = 0
        # Count of records dropped because the write failed (L11). Surfaced on
        # the next successful record and via `dropped_records` so silently
        # disappearing security events become visible.
        self._dropped = 0
        ensure_dir(path.parent, mode=0o700)
        reject_symlink(path)
        # Open append-binary so write() is atomic on POSIX for small records, and
        # we control text encoding ourselves.
        open_flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), open_flags, 0o600)
        self._fh = os.fdopen(fd, "ab", closefd=True)
        if sys.platform != "win32":
            with contextlib.suppress(OSError):
                os.fchmod(self._fh.fileno(), 0o600)
        if self._hash_chain:
            self._prev_hash, self._seq = self._scan_tail_state()
        # Self-announce so an empty log file always carries at least one record
        # naming the chain mode and the actor that opened it.
        self.emit("audit_log_opened", outcome=OUTCOME_OK, hash_chain=self._hash_chain)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def dropped_records(self) -> int:
        """Number of audit records lost to write failures since process start."""
        with self._lock:
            return self._dropped

    def emit(
        self,
        event: str,
        *,
        outcome: str = OUTCOME_OK,
        **payload: Any,
    ) -> None:
        if outcome not in _VALID_OUTCOMES:
            raise AuditLogError(f"invalid outcome {outcome!r}")
        _check_payload(event, payload)

        record: dict[str, Any] = {
            "ts": _utc_now_iso(),
            "event": event,
            "actor": _actor(),
            "outcome": outcome,
        }
        record.update(payload)

        with self._lock:
            if self._hash_chain:
                with FileLock(self._path, exclusive=True, timeout=5.0):
                    self._prev_hash, self._seq = self._scan_tail_state()
                    self._write_record(record)
            else:
                self._write_record(record)

    def _write_record(self, record: dict[str, Any]) -> None:
        if self._hash_chain:
            record["prev_hash"] = self._prev_hash or ""
            record["seq"] = self._seq
        # Surface any previously-dropped records so the gap is visible in-band.
        if self._dropped:
            record["dropped_audit_records"] = self._dropped
        line = _serialise(record)
        data = (line + "\n").encode("utf-8")
        try:
            self._fh.write(data)
            self._fh.flush()
            os.fsync(self._fh.fileno())
        except OSError as exc:
            # I/O failure must not abort the operation that triggered this audit
            # event — key material cannot be un-generated or un-deleted.  Fall
            # back to stderr so the failure is visible without crashing the app,
            # and track the loss so it is reported rather than vanishing silently.
            self._dropped += 1
            _log.error(
                "audit log write failed (%s): %s [%d dropped so far]",
                type(exc).__name__,
                exc,
                self._dropped,
            )
            return
        self._dropped = 0
        self._seq += 1
        if self._hash_chain:
            self._prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
            with contextlib.suppress(OSError):
                atomic_write_bytes(
                    self._tip_path,
                    (f"{self._prev_hash} {self._seq - 1}\n").encode("ascii"),
                )

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.flush()
            finally:
                self._fh.close()

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _scan_tail_state(self) -> tuple[str | None, int]:
        """Return ``(hash_of_last_record, next_seq)`` by reading tail-first.

        Reads up to _TAIL_CHUNK bytes from the end of the file to find the last
        non-empty line, avoiding an O(N) full-file scan on every emit(). The
        file is opened with ``O_NOFOLLOW`` so a symlink swapped in under the log
        path cannot redirect the read (L12). ``next_seq`` is one past the last
        record's ``seq`` (0 for an empty/seq-less log).
        """
        if not self._path.exists() or self._path.stat().st_size == 0:
            return None, 0
        with _open_ro_nofollow(self._path) as f:
            f.seek(0, 2)  # end
            size = f.tell()
            chunk = min(size, _TAIL_CHUNK)
            f.seek(-chunk, 2)
            tail = f.read(chunk)
        last: bytes | None = None
        # Find the last complete (newline-terminated) line in the chunk.
        for raw in reversed(tail.split(b"\n")):
            raw = raw.strip()
            if raw:
                last = raw
                break
        if last is None:
            # Tail chunk didn't contain a complete line — fall back to full scan.
            with _open_ro_nofollow(self._path) as f:
                for raw in f:
                    raw = raw.strip()
                    if raw:
                        last = raw
        if last is None:
            return None, 0
        return hashlib.sha256(last).hexdigest(), _seq_after(last)


def emit_best_effort(
    audit: AuditLog | None,
    event: str,
    *,
    outcome: str = OUTCOME_OK,
    **payload: Any,
) -> None:
    """Record an event that has already happened, and never raise doing so.

    ``emit`` is strict on purpose: an event outside the whitelist or a payload
    carrying a secret is a programming error, and tests must see it. In a
    running application it is the wrong moment to be strict. The services call
    this after the operation they describe has completed — a key generated, a
    card PIN changed, a token enrolled — so a refused *record* cannot mean the
    *operation* failed. Raising there is worse than losing the line: callers
    that read an exception as "this did not happen" undo work that did (see
    ``key_unlock_service._persist``, which deletes the key it just created).

    The loss is written to the diagnostic log rather than swallowed, which is
    the same treatment ``_write_record`` already gives an unwritable log file.
    """
    if audit is None:
        return
    try:
        audit.emit(event, outcome=outcome, **payload)
    except Exception:
        _log.exception("audit event %r was not recorded", event)


def verify_chain(path: Path) -> tuple[bool, int]:
    """Walk a hash-chained audit log and verify internal consistency.

    Returns `(ok, records_checked)`. Returns `(True, 0)` on an empty file. A
    `True` result means the file is internally consistent (chain links match,
    the `seq` counter starts at 0 and is gap-free, and the `.tip` matches the
    last record) — NOT that it is cryptographically authentic; see the module
    docstring for the threat model. The file and `.tip` are read with
    ``O_NOFOLLOW`` so a swapped symlink cannot redirect verification (L12).
    """
    if not path.exists() or path.stat().st_size == 0:
        return True, 0

    prev_hash: str | None = None
    expected_seq = 0
    count = 0
    with _open_ro_nofollow(path) as f:
        for raw in f:
            line_bytes = raw.rstrip(b"\n")
            line = line_bytes.decode("utf-8", errors="replace")
            if not line:
                continue
            count += 1
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                return False, count
            stored = obj.get("prev_hash")
            if stored is None:
                # File was written without hash_chain — treat as a non-chained log.
                if prev_hash is not None:
                    return False, count
            else:
                expected = prev_hash or ""
                if stored != expected:
                    return False, count
                # The seq counter must start at 0 and increase by exactly one;
                # a gap or non-zero start exposes truncation or record removal
                # even when an attacker recomputed the hash links.
                seq = obj.get("seq")
                if isinstance(seq, int):
                    if seq != expected_seq:
                        return False, count
                    expected_seq = seq + 1
                prev_hash = hashlib.sha256(line_bytes).hexdigest()
    if prev_hash is None:
        return True, count
    return _verify_tip(path, prev_hash, expected_seq), count


def _verify_tip(path: Path, prev_hash: str, expected_seq: int) -> bool:
    """Check the ``.tip`` sidecar against the walked chain head."""
    tip_path = path.with_name(path.name + ".tip")
    if not tip_path.exists():
        # .tip was introduced in 1.0.4; logs written by earlier versions
        # are tip-less but internally consistent — skip the tip check so
        # an upgrade does not produce a spurious tamper warning.
        _log.debug("verify_chain: no .tip file for %s (pre-1.0.4 log?)", path)
        return True
    try:
        with _open_ro_nofollow(tip_path) as tf:
            tip_raw = tf.read(256).decode("ascii", errors="replace").strip()
    except OSError:
        return False
    tip_fields = tip_raw.split()
    tip_hash = tip_fields[0] if tip_fields else ""
    if len(tip_hash) != 64 or tip_hash != prev_hash:
        return False
    # If the tip records the last seq, it must match what we walked.
    return not (
        len(tip_fields) > 1
        and tip_fields[1].isdigit()
        and int(tip_fields[1]) != expected_seq - 1
    )
