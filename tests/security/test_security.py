"""Security regression tests (planv2.md §10, item 41).

Covers: log sanitization, audit-log isolation, atomic write integrity,
argv passphrase safety, and path whitelist enforcement.

All tests in this module are pure-unit tests (no GPG binary required).
GPG-level argv and tamper tests live in tests/integration/.
"""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import structlog

from gpg_meister.storage.atomic_write import atomic_write_bytes
from gpg_meister.storage.audit_log import AuditLog, AuditLogError
from gpg_meister.storage.log_config import _REDACTED, sensitive_data_filter

# ---------------------------------------------------------------------------
# Log sanitization
# ---------------------------------------------------------------------------


class _FakeLogger:
    pass


def _apply(event_dict: dict[str, object]) -> dict[str, object]:
    return dict(sensitive_data_filter(_FakeLogger(), "info", event_dict))


@pytest.mark.parametrize(
    "key,value",
    [
        ("passphrase", "supersecret"),
        ("password", "hunter2"),
        ("secret", "my-secret"),
        ("private_key", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc"),
        ("private_key_armored", "armored key data"),
        ("armored_private", "armored private data"),
        ("plaintext", "hello world"),
        ("decrypted", "decrypted content"),
        ("vault_key", "raw bytes"),
        ("derived_key", "derived bytes"),
        ("salt", "0" * 32),
        ("pin", "1234"),
        ("token", "bearer abc"),
    ],
)
def test_sensitive_key_is_redacted_in_log(key: str, value: str) -> None:
    result = _apply({"event": "test_event", key: value})
    assert result[key] == _REDACTED, f"key '{key}' with value '{value}' was not redacted"


def test_non_sensitive_key_passes_through() -> None:
    result = _apply({"event": "key_generated", "fingerprint": "ABCD" * 10, "outcome": "ok"})
    assert result["fingerprint"] == "ABCD" * 10
    assert result["outcome"] == "ok"


def test_pgp_private_block_in_arbitrary_value_redacted() -> None:
    payload = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nkJz...\n-----END PGP PRIVATE KEY BLOCK-----"
    result = _apply({"event": "test_event", "arbitrary_field": payload})
    assert result["arbitrary_field"] == _REDACTED


def test_pgp_message_block_in_value_redacted() -> None:
    payload = "-----BEGIN PGP MESSAGE-----\nencoded\n-----END PGP MESSAGE-----"
    result = _apply({"event": "test_event", "ciphertext": payload})
    assert result["ciphertext"] == _REDACTED


def test_structlog_output_never_contains_passphrase_string(tmp_path: Path) -> None:
    """Configure logging and emit an event that would contain a passphrase;
    verify the output file contains no trace of the raw passphrase."""
    from gpg_meister.storage.log_config import configure_logging

    log_path = tmp_path / "app.log"
    configure_logging(log_file=log_path, level=10)  # DEBUG

    logger = structlog.get_logger()
    # This call should be intercepted by the deny-list filter.
    logger.info("test_event", passphrase="my_super_secret_value", fingerprint="AABB")

    content = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    assert "my_super_secret_value" not in content
    assert _REDACTED in content or "AABB" in content  # event was logged, passphrase was not


# ---------------------------------------------------------------------------
# Audit log isolation
# ---------------------------------------------------------------------------


def test_audit_log_rejects_unknown_events(tmp_path: Path) -> None:
    with AuditLog(tmp_path / "audit.log") as log:  # noqa: SIM117
        with pytest.raises(AuditLogError, match="whitelist"):
            log.emit("totally_unknown_event_xyz")


def test_audit_log_rejects_forbidden_keys(tmp_path: Path) -> None:
    with AuditLog(tmp_path / "audit.log") as log:  # noqa: SIM117
        with pytest.raises(AuditLogError, match="forbidden"):
            log.emit("key_generated", outcome="ok", passphrase="secret")


def test_audit_log_contains_required_envelope_fields(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path) as log:
        log.emit("key_generated", outcome="ok", fingerprint="ABCD1234")

    records = [json.loads(line) for line in log_path.read_text().splitlines() if line]
    # Skip the self-announce record.
    event_record = next(r for r in records if r["event"] == "key_generated")
    assert "ts" in event_record
    assert "actor" in event_record
    assert "outcome" in event_record
    assert event_record["fingerprint"] == "ABCD1234"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_audit_log_file_permissions_are_0600(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    with AuditLog(log_path):
        pass
    mode = stat.S_IMODE(log_path.stat().st_mode)
    assert mode == 0o600


def test_two_audit_logs_do_not_share_state(tmp_path: Path) -> None:
    log_a = AuditLog(tmp_path / "a.log")
    log_b = AuditLog(tmp_path / "b.log")

    log_a.emit("key_generated", outcome="ok", fingerprint="AAAA")
    log_b.emit("vault_created", outcome="ok", path="/tmp/v", key_count=1, cipher="x", sha256="y")

    log_a.close()
    log_b.close()

    events_a = {
        json.loads(line)["event"]
        for line in (tmp_path / "a.log").read_text().splitlines()
        if line
    }
    events_b = {
        json.loads(line)["event"]
        for line in (tmp_path / "b.log").read_text().splitlines()
        if line
    }
    assert "key_generated" in events_a
    assert "key_generated" not in events_b
    assert "vault_created" in events_b
    assert "vault_created" not in events_a


# ---------------------------------------------------------------------------
# Atomic write integrity
# ---------------------------------------------------------------------------


def test_atomic_write_leaves_no_tmp_on_success(tmp_path: Path) -> None:
    target = tmp_path / "data.bin"
    atomic_write_bytes(target, b"hello world")
    leftovers = [p for p in tmp_path.iterdir() if ".tmp" in p.name or p.name.endswith(".tmp")]
    assert leftovers == []


def test_atomic_write_does_not_corrupt_existing_file_on_os_error(tmp_path: Path) -> None:
    target = tmp_path / "data.bin"
    target.write_bytes(b"original content")

    with patch("os.replace", side_effect=OSError("disk full")), pytest.raises(OSError):
        atomic_write_bytes(target, b"new content")

    # Original file must remain intact.
    assert target.read_bytes() == b"original content"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions only")
def test_atomic_write_sets_mode_0600(tmp_path: Path) -> None:
    target = tmp_path / "secret.bin"
    atomic_write_bytes(target, b"data", mode=0o600)
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode & 0o177 == 0  # no group or other bits


# ---------------------------------------------------------------------------
# argv passphrase guard
# ---------------------------------------------------------------------------


def test_reject_passphrase_in_argv_raises_on_match() -> None:
    from gpg_meister.services.validation import reject_passphrase_in_argv

    with pytest.raises(Exception, match="passphrase"):
        reject_passphrase_in_argv(["--batch", "--passphrase", "hunter2"], b"hunter2")


def test_reject_passphrase_in_argv_passes_when_absent() -> None:
    from gpg_meister.services.validation import reject_passphrase_in_argv

    reject_passphrase_in_argv(["--batch", "--homedir", "/tmp/x", "--passphrase-fd", "0"], b"hunter2")


# ---------------------------------------------------------------------------
# GPG binary path whitelist
# ---------------------------------------------------------------------------


def test_untrusted_path_without_hash_pin_is_rejected(tmp_path: Path) -> None:
    from gpg_meister.startup.gpg_detector import GPGDetectionError, detect

    fake_binary = tmp_path / "evil-gpg"
    fake_binary.write_bytes(b"#!/bin/sh\necho 'gpg (GnuPG) 2.4.0'\n")
    fake_binary.chmod(0o755)

    with pytest.raises(GPGDetectionError):
        detect(user_override_path=str(fake_binary), trusted_hash=None)
