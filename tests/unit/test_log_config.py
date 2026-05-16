from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest
import structlog

from gpg_meister.storage.log_config import (
    _AUDIT_EVENT_NAMES,
    _REDACTED,
    _open_log_file,
    configure_logging,
    sensitive_data_filter,
)


class _FakeLogger:
    pass


def _apply(event_dict: dict[str, object]) -> dict[str, object]:
    return dict(sensitive_data_filter(_FakeLogger(), "info", event_dict))


@pytest.mark.parametrize(
    "key",
    [
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
    ],
)
def test_deny_list_key_redacted(key: str) -> None:
    result = _apply({"event": "test", key: "supersecret"})
    assert result[key] == _REDACTED


def test_non_sensitive_key_not_redacted() -> None:
    result = _apply({"event": "test", "fingerprint": "ABCD" * 10, "sha256": "abc123"})
    assert result["fingerprint"] == "ABCD" * 10
    assert result["sha256"] == "abc123"


def test_pgp_private_key_block_redacted() -> None:
    payload = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsome data\n-----END PGP PRIVATE KEY BLOCK-----"
    result = _apply({"event": "test", "data": payload})
    assert result["data"] == _REDACTED


def test_pgp_message_block_redacted() -> None:
    payload = "-----BEGIN PGP MESSAGE-----\nencrypted\n-----END PGP MESSAGE-----"
    result = _apply({"event": "test", "content": payload})
    assert result["content"] == _REDACTED


def test_non_pgp_long_string_not_redacted() -> None:
    long_b64 = "A" * 200
    result = _apply({"event": "test", "logo": long_b64})
    assert result["logo"] == long_b64


def test_audit_event_names_are_non_empty() -> None:
    assert len(_AUDIT_EVENT_NAMES) > 10


def test_configure_logging_runs(tmp_path: Path) -> None:
    configure_logging(log_file=tmp_path / "diag.log", dev=True)
    logger = structlog.get_logger("test")
    logger.info("hello", fingerprint="ABCD" * 10)


def test_configure_logging_creates_file(tmp_path: Path) -> None:
    log_file = tmp_path / "subdir" / "diag.log"
    configure_logging(log_file=log_file, dev=True)
    assert log_file.parent.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_log_file_mode_0600(tmp_path: Path) -> None:
    log_file = tmp_path / "diag.log"
    configure_logging(log_file=log_file, dev=True)
    mode = stat.S_IMODE(log_file.stat().st_mode)
    assert mode == 0o600


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_log_file_rejects_symlink_path(tmp_path: Path) -> None:
    target = tmp_path / "target.log"
    target.write_text("", encoding="utf-8")
    link = tmp_path / "diag.log"
    os.symlink(target, link)

    with pytest.raises((OSError, RuntimeError)):
        _open_log_file(link)
