"""Append-only audit log for security-relevant events.

This is a deliberately separate channel from the diagnostic log (planv2.md §2.11):

- Different sink file, different rotation policy (none).
- Whitelisted event names — anything else is rejected.
- Forbidden keys (the deny-list from §5.4) raise at runtime; the record is dropped
  and a diagnostic entry is recorded instead.
- Optional hash chain: each record carries `prev_hash`, the SHA-256 of the previous
  serialised record. Tampering becomes detectable cheaply by re-walking the file.

The log is opened in append mode with mode 0o600 on POSIX. Concurrent writers from
the same process are serialised through an internal lock; hash-chained writes also
take an advisory file lock while scanning and appending.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sys
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from gpg_meister.storage.file_lock import FileLock
from gpg_meister.storage.permissions import _fchmod_nofollow, ensure_dir, reject_symlink

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
        "vault_created",
        "vault_imported",
        "vault_import_failed",
        "config_loaded",
        "config_saved",
    }
)

# Keys that must never appear in an audit payload. These are sensitive values that
# belong in SecureBytes, not in any persisted record.
FORBIDDEN_KEYS: Final[frozenset[str]] = frozenset(
    {
        "passphrase",
        "password",
        "secret",
        "private_key",
        "private_key_armored",
        "armored_private",
        "plaintext",
        "decrypted",
        "vault_key",
        "derived_key",
        "salt",
        "pin",
        "token",
    }
)

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


def _check_payload(event: str, payload: Mapping[str, Any]) -> None:
    if event not in ALLOWED_EVENTS:
        raise AuditLogError(f"event {event!r} is not in the audit whitelist")
    _check_payload_keys(payload, reserved={"event", "ts", "actor", "outcome", "prev_hash"})


def _check_payload_keys(obj: Mapping[str, Any], *, reserved: frozenset[str] = frozenset()) -> None:
    for key, value in obj.items():
        if key in FORBIDDEN_KEYS:
            raise AuditLogError(f"forbidden key {key!r} in audit payload")
        if reserved and key in reserved:
            raise AuditLogError(f"key {key!r} is reserved for the audit envelope")
        if isinstance(value, dict):
            _check_payload_keys(value)


def _serialise(record: Mapping[str, Any]) -> str:
    """One JSON object per line. Sorted keys for stable hashing."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class AuditLog:
    """Append-only audit log.

    Construct once per process; pass the instance to anything that needs to emit
    audit events. Closing is optional — the file handle is kept open for the
    lifetime of the process and flushed on every record.
    """

    def __init__(self, path: Path, *, hash_chain: bool = False) -> None:
        self._path = path
        self._hash_chain = hash_chain
        self._lock = threading.Lock()
        self._prev_hash: str | None = None
        ensure_dir(path.parent, mode=0o700)
        reject_symlink(path)
        # Open append-binary so write() is atomic on POSIX for small records, and
        # we control text encoding ourselves.
        self._fh = path.open("ab")
        if sys.platform != "win32":
            with contextlib.suppress(OSError):
                _fchmod_nofollow(path, 0o600)
        if self._hash_chain:
            self._prev_hash = self._scan_for_last_hash()
        # Self-announce so an empty log file always carries at least one record
        # naming the chain mode and the actor that opened it.
        self.emit("audit_log_opened", outcome=OUTCOME_OK, hash_chain=self._hash_chain)

    @property
    def path(self) -> Path:
        return self._path

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
                    self._prev_hash = self._scan_for_last_hash()
                    self._write_record(record)
            else:
                self._write_record(record)

    def _write_record(self, record: dict[str, Any]) -> None:
        if self._hash_chain:
            record["prev_hash"] = self._prev_hash or ""
        line = _serialise(record)
        data = (line + "\n").encode("utf-8")
        self._fh.write(data)
        self._fh.flush()
        os.fsync(self._fh.fileno())
        if self._hash_chain:
            self._prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()

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

    def _scan_for_last_hash(self) -> str | None:
        """Return the SHA-256 of the last record line in O(1) by reading tail-first.

        Reads up to _TAIL_CHUNK bytes from the end of the file to find the
        last non-empty line, avoiding an O(N) full-file scan on every emit().
        """
        if not self._path.exists() or self._path.stat().st_size == 0:
            return None
        with self._path.open("rb") as f:
            f.seek(0, 2)  # end
            size = f.tell()
            chunk = min(size, _TAIL_CHUNK)
            f.seek(-chunk, 2)
            tail = f.read(chunk)
        # Find the last complete (newline-terminated) line in the chunk.
        lines = tail.split(b"\n")
        for raw in reversed(lines):
            raw = raw.strip()
            if raw:
                return hashlib.sha256(raw).hexdigest()
        # Tail chunk didn't contain a complete line — fall back to full scan.
        with self._path.open("rb") as f:
            last: bytes | None = None
            for raw in f:
                raw = raw.strip()
                if raw:
                    last = raw
        if last is None:
            return None
        return hashlib.sha256(last).hexdigest()


def verify_chain(path: Path) -> tuple[bool, int]:
    """Walk a hash-chained audit log and verify integrity.

    Returns `(ok, records_checked)`. Returns `(True, 0)` on an empty file.
    """
    if not path.exists() or path.stat().st_size == 0:
        return True, 0

    prev_hash: str | None = None
    count = 0
    with path.open("rb") as f:
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
                prev_hash = hashlib.sha256(line_bytes).hexdigest()
    return True, count
