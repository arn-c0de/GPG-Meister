from __future__ import annotations

import json
from pathlib import Path

import pytest

from gpg_meister.models.key_info import KeyAlgorithm
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.errors import GPGServiceError
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.services.key_service import ImportConflict, KeyService
from gpg_meister.services.message_service import MessageService
from gpg_meister.storage.audit_log import AuditLog

pytestmark = pytest.mark.integration


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.log")


@pytest.fixture
def key_service(isolated_gpg: GPGService, audit: AuditLog) -> KeyService:
    return KeyService(gpg=isolated_gpg, audit=audit)


@pytest.fixture
def message_service(isolated_gpg: GPGService, audit: AuditLog) -> MessageService:
    return MessageService(gpg=isolated_gpg, audit=audit)


def _make_key(service: KeyService) -> str:
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        info = service.create(
            name="Alice",
            email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA,
            length=255,
            expiry="2y",
            passphrase=pw,
        )
    return info.fingerprint


def test_create_emits_audit_event(audit: AuditLog, key_service: KeyService) -> None:
    fp = _make_key(key_service)
    audit.close()
    events = [json.loads(line) for line in audit.path.read_text().splitlines() if line]
    by_event = {e["event"]: e for e in events}
    assert "key_generated" in by_event
    assert by_event["key_generated"]["fingerprint"] == fp


def test_plan_import_detects_new_key(
    key_service: KeyService, isolated_gpg: GPGService, tmp_path: Path
) -> None:
    fp = _make_key(key_service)
    armored = isolated_gpg.export_public_key(fp)

    # Spin up a second keyring and ask its key service to plan the import.
    from gpg_meister.services.gpg_service import GPGServiceConfig

    other_home = tmp_path / "other-gnupg"
    other_home.mkdir(mode=0o700)
    other = GPGService(GPGServiceConfig(binary_path=isolated_gpg.config.binary_path, home_dir=other_home))
    other_audit = AuditLog(tmp_path / "other-audit.log")
    other_ks = KeyService(gpg=other, audit=other_audit)

    plan = other_ks.plan_import(armored)
    assert any(e.fingerprint == fp and e.conflict is ImportConflict.NEW for e in plan)


def test_plan_import_detects_existing_public(
    key_service: KeyService, isolated_gpg: GPGService
) -> None:
    fp = _make_key(key_service)
    armored = isolated_gpg.export_public_key(fp)
    plan = key_service.plan_import(armored)
    # Local keyring already has both pub and secret, so conflict is highest tier.
    assert any(
        e.fingerprint == fp and e.conflict is ImportConflict.ALREADY_HAS_PRIVATE
        for e in plan
    )


def test_delete_records_audit(audit: AuditLog, key_service: KeyService) -> None:
    fp = _make_key(key_service)
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        key_service.delete(fp, including_secret=True, passphrase=pw)
    audit.close()
    events = [json.loads(line) for line in audit.path.read_text().splitlines() if line]
    by_event = [e for e in events if e["event"] == "key_deleted"]
    assert by_event and by_event[0]["fingerprint"] == fp


def test_encrypt_decrypt_via_message_service(
    key_service: KeyService, message_service: MessageService
) -> None:
    fp = _make_key(key_service)
    enc = message_service.encrypt(b"hello world", recipient_fingerprints=[fp])
    assert enc.armored_ciphertext.startswith("-----BEGIN PGP MESSAGE-----")
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        dec = message_service.decrypt(enc.armored_ciphertext.encode("utf-8"), passphrase=pw)
    assert dec.plaintext == b"hello world"
    assert dec.signer_fingerprint is None
    assert dec.signature_valid is False
    assert dec.decrypted_with_fingerprint is not None
    assert len(dec.decrypted_with_fingerprint) == 40


def test_encrypt_with_signature(
    key_service: KeyService, message_service: MessageService
) -> None:
    fp = _make_key(key_service)
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        enc = message_service.encrypt(
            b"signed and sealed",
            recipient_fingerprints=[fp],
            sign_with=fp,
            passphrase=pw,
        )
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        dec = message_service.decrypt(enc.armored_ciphertext.encode("utf-8"), passphrase=pw)
    assert dec.plaintext == b"signed and sealed"
    assert dec.signer_fingerprint is not None
    assert dec.signature_valid is True
    assert dec.decrypted_with_fingerprint is not None
    assert len(dec.decrypted_with_fingerprint) == 40


def test_decrypt_failure_records_audit(
    audit: AuditLog, key_service: KeyService, message_service: MessageService
) -> None:
    fp = _make_key(key_service)
    enc = message_service.encrypt(b"x", recipient_fingerprints=[fp])
    with SecureBytes.from_bytes(b"wrong pw") as bad, pytest.raises(GPGServiceError):
        message_service.decrypt(enc.armored_ciphertext.encode("utf-8"), passphrase=bad)
    audit.close()
    events = [json.loads(line) for line in audit.path.read_text().splitlines() if line]
    assert any(e["event"] == "message_decrypt_failed" for e in events)


def test_export_private_records_audit(
    audit: AuditLog, key_service: KeyService
) -> None:
    fp = _make_key(key_service)
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        armored = key_service.export_private(fp, pw)
    assert "PRIVATE KEY" in armored
    audit.close()
    events = [json.loads(line) for line in audit.path.read_text().splitlines() if line]
    assert any(
        e["event"] == "key_exported_private" and e["fingerprint"] == fp for e in events
    )
