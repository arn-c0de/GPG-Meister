from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

import pytest

from gpg_meister.storage.audit_log import (
    OUTCOME_FAILED,
    OUTCOME_OK,
    AuditLog,
    AuditLogError,
    verify_chain,
)


def _read_records(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_emits_record_with_envelope(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path) as log:
        log.emit("key_generated", outcome=OUTCOME_OK, fingerprint="ABC")

    records = _read_records(log_path)
    # First record is the self-announce "audit_log_opened", second is ours.
    assert len(records) == 2
    assert records[0]["event"] == "audit_log_opened"
    assert records[1]["event"] == "key_generated"
    assert records[1]["fingerprint"] == "ABC"
    for r in records:
        assert "ts" in r
        assert "actor" in r
        assert "outcome" in r


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_audit_file_is_mode_0600(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path):
        pass
    mode = stat.S_IMODE(log_path.stat().st_mode)
    assert mode == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_audit_log_rejects_symlink_path(tmp_path: Path) -> None:
    target = tmp_path / "target.log"
    target.write_text("", encoding="utf-8")
    link = tmp_path / "audit.log"
    os.symlink(target, link)

    with pytest.raises((OSError, RuntimeError)):
        AuditLog(link)


def test_unknown_event_rejected(tmp_path: Path) -> None:
    with (
        AuditLog(tmp_path / "audit.log") as log,
        pytest.raises(AuditLogError, match="whitelist"),
    ):
        log.emit("ad_hoc_debug_event")


def test_forbidden_key_rejected(tmp_path: Path) -> None:
    with (
        AuditLog(tmp_path / "audit.log") as log,
        pytest.raises(AuditLogError, match="forbidden"),
    ):
        log.emit("key_generated", passphrase="secret")


def test_reserved_key_rejected(tmp_path: Path) -> None:
    with (
        AuditLog(tmp_path / "audit.log") as log,
        pytest.raises(AuditLogError, match="reserved"),
    ):
        log.emit("key_generated", actor="someone")


def test_invalid_outcome_rejected(tmp_path: Path) -> None:
    with AuditLog(tmp_path / "audit.log") as log, pytest.raises(AuditLogError, match="outcome"):
        log.emit("key_generated", outcome="maybe")


def test_hash_chain_links_records(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("key_generated", fingerprint="A")
        log.emit("vault_created", outcome=OUTCOME_OK)

    records = _read_records(log_path)
    # First record (self-announce) has empty prev_hash.
    assert records[0]["prev_hash"] == ""
    # Subsequent records have non-empty prev_hash.
    assert records[1]["prev_hash"] != ""
    assert records[2]["prev_hash"] != ""

    ok, count = verify_chain(log_path)
    assert ok
    assert count == 3


def test_chain_detects_tampering(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("key_generated", fingerprint="A")
        log.emit("vault_created", outcome=OUTCOME_OK)

    # Modify a middle record.
    lines = log_path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[1])
    obj["fingerprint"] = "B"
    lines[1] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, _ = verify_chain(log_path)
    assert not ok


def test_chain_resumes_across_reopen(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("key_generated", fingerprint="A")
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("vault_created", outcome=OUTCOME_OK)

    ok, count = verify_chain(log_path)
    assert ok
    # 2 audit_log_opened + 1 key_generated + 1 vault_created = 4 records.
    assert count == 4


def test_failed_outcome_recorded(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path) as log:
        log.emit("vault_import_failed", outcome=OUTCOME_FAILED, reason="wrong passphrase")

    records = _read_records(log_path)
    failed = [r for r in records if r["event"] == "vault_import_failed"]
    assert failed[0]["outcome"] == OUTCOME_FAILED
    assert failed[0]["reason"] == "wrong passphrase"


def test_concurrent_emits_are_serialised(tmp_path: Path) -> None:
    """Two threads emitting simultaneously must produce well-formed JSON lines."""
    import threading

    log_path = tmp_path / "audit.log"
    log = AuditLog(log_path)
    errors: list[Exception] = []

    def worker(i: int) -> None:
        try:
            for j in range(50):
                log.emit("key_generated", fingerprint=f"FP{i:02d}{j:02d}")
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log.close()

    assert not errors
    records = _read_records(log_path)
    # 1 announce + 4 * 50 emits = 201
    assert len(records) == 201
    # Every line must be valid JSON (covered by _read_records succeeding).


def test_empty_chain_verification(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    ok, count = verify_chain(log_path)
    assert ok
    assert count == 0


def test_forbidden_key_in_list_rejected(tmp_path: Path) -> None:
    """FORBIDDEN_KEYS check must recurse into list/tuple values."""
    with (
        AuditLog(tmp_path / "audit.log") as log,
        pytest.raises(AuditLogError, match="forbidden"),
    ):
        log.emit("key_generated", details=[{"passphrase": "secret"}])


def test_secret_in_nested_list_rejected(tmp_path: Path) -> None:
    """Secret material hidden one list deeper (list-of-lists) must still raise."""
    pgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----"
    with (
        AuditLog(tmp_path / "audit.log") as log,
        pytest.raises(AuditLogError, match="secret key material"),
    ):
        log.emit("key_generated", rows=[[pgp]])


def test_chain_tip_detects_tail_truncation(tmp_path: Path) -> None:
    """verify_chain must return False when the tip file shows records were removed."""
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("key_generated", fingerprint="A")
        log.emit("vault_created", outcome=OUTCOME_OK)

    # Remove the last record from the log file.
    raw = log_path.read_bytes()
    lines = raw.rstrip(b"\n").split(b"\n")
    log_path.write_bytes(b"\n".join(lines[:-1]) + b"\n")

    ok, _ = verify_chain(log_path)
    assert not ok


def test_chain_verification_accepts_missing_tip_file(tmp_path: Path) -> None:
    # Logs written by 1.0.3 have no .tip sidecar; verify_chain must not raise
    # a false tamper alarm when upgrading from those older versions.
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("key_generated", fingerprint="A")

    log_path.with_name("audit.log.tip").unlink()

    ok, count = verify_chain(log_path)
    assert ok
    assert count >= 1


def test_chain_verification_rejects_malformed_tip_file(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("key_generated", fingerprint="A")

    log_path.with_name("audit.log.tip").write_text("not-a-sha256\n", encoding="ascii")

    ok, _ = verify_chain(log_path)
    assert not ok


def test_chain_records_carry_monotonic_seq(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("key_generated", fingerprint="A")
        log.emit("vault_created")

    seqs = [r["seq"] for r in _read_records(log_path)]
    assert seqs == [0, 1, 2]


def test_chain_seq_continues_across_reopen(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("key_generated", fingerprint="A")
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("vault_created")

    seqs = [r["seq"] for r in _read_records(log_path)]
    assert seqs == [0, 1, 2, 3]
    ok, count = verify_chain(log_path)
    assert ok
    assert count == 4


def test_chain_detects_seq_gap_even_if_hashes_recomputed(tmp_path: Path) -> None:
    """A same-process attacker who deletes a middle record and rebuilds the hash
    links is still caught by the seq gap."""
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path, hash_chain=True) as log:
        log.emit("key_generated", fingerprint="A")
        log.emit("vault_created")
        log.emit("key_deleted", fingerprint="A")

    lines = [json.loads(line) for line in log_path.read_text().splitlines() if line]
    # Drop the second record, then rebuild the prev_hash chain so only seq is wrong.
    del lines[1]
    prev_hash = ""
    rebuilt: list[str] = []
    for obj in lines:
        obj["prev_hash"] = prev_hash
        line = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        rebuilt.append(line)
        prev_hash = hashlib.sha256(line.encode()).hexdigest()
    log_path.write_text("\n".join(rebuilt) + "\n")
    # Fix the tip so only the seq counter exposes the deletion.
    log_path.with_name("audit.log.tip").write_text(prev_hash + "\n", encoding="ascii")

    ok, _ = verify_chain(log_path)
    assert not ok


def test_dropped_records_counter_surfaces_write_failures(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    log = AuditLog(log_path)
    assert log.dropped_records == 0
    # Force the next write to fail, then recover.
    real_write = log._fh.write

    def _boom(_data: bytes) -> int:
        raise OSError("disk full")

    log._fh.write = _boom  # type: ignore[method-assign]
    log.emit("key_generated", fingerprint="A")
    assert log.dropped_records == 1
    log._fh.write = real_write  # type: ignore[method-assign]
    log.emit("vault_created")
    # The recovery record reports the prior loss in-band, and the counter resets.
    assert log.dropped_records == 0
    records = _read_records(log_path)
    assert any(r.get("dropped_audit_records") == 1 for r in records)
    log.close()


def test_forbidden_key_matching_is_case_insensitive(tmp_path: Path) -> None:
    with AuditLog(tmp_path / "audit.log") as log:
        for bad_key in ("Passphrase", "master_passphrase", "priv_key"):
            with pytest.raises(AuditLogError, match="forbidden"):
                log.emit("key_generated", **{bad_key: "x"})


def test_metadata_flags_mentioning_secrets_are_allowed(tmp_path: Path) -> None:
    # Boolean/metadata keys that merely *mention* a secret stem must not be
    # redacted as if they held the secret itself.
    with AuditLog(tmp_path / "audit.log") as log:
        log.emit("key_deleted", fingerprint="A", including_secret=True, has_private_key=False)
