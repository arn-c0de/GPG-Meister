"""Full lifecycle integration test (planv2.md §10, item 42).

Exercises the complete happy path across all services:
  1. Generate a key pair.
  2. Encrypt a message to that key.
  3. Sign a message with that key.
  4. Export the key to a vault.
  5. Import the key into a fresh, isolated keyring.
  6. Decrypt the message in the new keyring.
  7. Verify the signature in the new keyring.

All steps run against real GPG processes; this test is skipped when no GnuPG
binary is available (same as other integration tests).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gpg_meister.models.key_info import KeyAlgorithm
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.gpg_service import GPGService, GPGServiceConfig
from gpg_meister.services.key_service import KeyService
from gpg_meister.services.message_service import MessageService
from gpg_meister.services.vault_service import VaultService
from gpg_meister.storage.audit_log import AuditLog

pytestmark = pytest.mark.integration

_PASSPHRASE = b"correct horse battery staple"
_VAULT_PASSPHRASE = b"vault master secret phrase here"
_PLAINTEXT = b"Hello, world! This is a secret message."


@pytest.fixture
def source_audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "source-audit.log")


@pytest.fixture
def dest_audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "dest-audit.log")


@pytest.fixture
def source_gpg(gpg_binary: Path, tmp_path: Path) -> GPGService:
    home = tmp_path / "source-gnupg"
    home.mkdir(mode=0o700)
    return GPGService(GPGServiceConfig(binary_path=gpg_binary, home_dir=home))


@pytest.fixture
def dest_gpg(gpg_binary: Path, tmp_path: Path) -> GPGService:
    home = tmp_path / "dest-gnupg"
    home.mkdir(mode=0o700)
    return GPGService(GPGServiceConfig(binary_path=gpg_binary, home_dir=home))


def test_full_key_encrypt_sign_vault_import_decrypt_verify(
    tmp_path: Path,
    source_gpg: GPGService,
    dest_gpg: GPGService,
    source_audit: AuditLog,
    dest_audit: AuditLog,
) -> None:
    key_svc = KeyService(gpg=source_gpg, audit=source_audit)
    msg_svc = MessageService(gpg=source_gpg, audit=source_audit)
    vault_svc_src = VaultService(gpg=source_gpg, audit=source_audit)
    vault_svc_dst = VaultService(gpg=dest_gpg, audit=dest_audit)

    # 1. Generate key in source keyring.
    with SecureBytes.from_bytes(_PASSPHRASE) as pp:
        key_info = key_svc.create(
            name="Alice",
            email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA,
            length=255,
            expiry="2y",
            passphrase=pp,
        )
    fp = key_info.fingerprint
    assert key_info.has_private_key

    # 2. Encrypt a message to that key.
    encrypt_result = msg_svc.encrypt(_PLAINTEXT, recipient_fingerprints=[fp])
    ciphertext = encrypt_result.armored_ciphertext.encode()

    # 3. Sign a message with that key.
    with SecureBytes.from_bytes(_PASSPHRASE) as pp:
        sign_result = msg_svc.sign(_PLAINTEXT, fingerprint=fp, passphrase=pp, detached=True)
    signature = sign_result.armored_signature.encode()

    # 4. Export key to vault.
    vault_path = tmp_path / "alice.gpgm"
    with (
        SecureBytes.from_bytes(_VAULT_PASSPHRASE) as vpp,
        SecureBytes.from_bytes(_PASSPHRASE) as gpp,
    ):
        descriptor = vault_svc_src.create(
            target_path=vault_path,
            master_passphrase=vpp,
            gpg_passphrase=gpp,
            fingerprints=[fp],
            description="lifecycle test",
        )
    assert descriptor.key_count == 1
    assert vault_path.exists()

    # 5. Import key into destination keyring.
    with SecureBytes.from_bytes(_VAULT_PASSPHRASE) as vpp:
        imported = vault_svc_dst.import_keys(
            source_path=vault_path, master_passphrase=vpp
        )
    assert fp in imported

    # Verify the key is now present in the destination keyring.
    dest_keys = dest_gpg.list_keys()
    assert any(k.fingerprint == fp for k in dest_keys)

    # 6. Decrypt the ciphertext in the destination keyring.
    dest_msg_svc = MessageService(gpg=dest_gpg, audit=dest_audit)
    with SecureBytes.from_bytes(_PASSPHRASE) as pp:
        decrypt_result = dest_msg_svc.decrypt(ciphertext, passphrase=pp)
    assert decrypt_result.plaintext == _PLAINTEXT

    # 7. Verify the detached signature in the destination keyring.
    verify_result = dest_msg_svc.verify(_PLAINTEXT, detached_signature=signature)
    assert verify_result.signature_valid
    assert verify_result.signer_fingerprint == fp


def test_vault_export_includes_only_selected_keys(
    tmp_path: Path,
    source_gpg: GPGService,
    source_audit: AuditLog,
) -> None:
    key_svc = KeyService(gpg=source_gpg, audit=source_audit)
    vault_svc = VaultService(gpg=source_gpg, audit=source_audit)

    with SecureBytes.from_bytes(_PASSPHRASE) as pp:
        key_a = key_svc.create(
            name="Alice", email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA, length=255, expiry="2y", passphrase=pp,
        )
        key_b = key_svc.create(
            name="Bob", email="bob@example.org",
            algorithm=KeyAlgorithm.EDDSA, length=255, expiry="2y", passphrase=pp,
        )

    vault_path = tmp_path / "partial.gpgm"
    with (
        SecureBytes.from_bytes(_VAULT_PASSPHRASE) as vpp,
        SecureBytes.from_bytes(_PASSPHRASE) as gpp,
    ):
        descriptor = vault_svc.create(
            target_path=vault_path,
            master_passphrase=vpp,
            gpg_passphrase=gpp,
            fingerprints=[key_a.fingerprint],  # only Alice
        )

    assert descriptor.key_count == 1

    with SecureBytes.from_bytes(_VAULT_PASSPHRASE) as vpp:
        preview = vault_svc.preview(source_path=vault_path, master_passphrase=vpp)

    fps_in_vault = {e.fingerprint for e in preview.keys}
    assert key_a.fingerprint in fps_in_vault
    assert key_b.fingerprint not in fps_in_vault


def test_encrypt_to_imported_vault_key(
    tmp_path: Path,
    source_gpg: GPGService,
    dest_gpg: GPGService,
    source_audit: AuditLog,
    dest_audit: AuditLog,
) -> None:
    """After importing a public key from a vault, the dest keyring can encrypt to it."""
    key_svc = KeyService(gpg=source_gpg, audit=source_audit)
    vault_svc_src = VaultService(gpg=source_gpg, audit=source_audit)

    with SecureBytes.from_bytes(_PASSPHRASE) as pp:
        key_info = key_svc.create(
            name="Charlie", email="charlie@example.org",
            algorithm=KeyAlgorithm.EDDSA, length=255, expiry="2y", passphrase=pp,
        )
    fp = key_info.fingerprint

    vault_path = tmp_path / "charlie.gpgm"
    with (
        SecureBytes.from_bytes(_VAULT_PASSPHRASE) as vpp,
        SecureBytes.from_bytes(_PASSPHRASE) as gpp,
    ):
        vault_svc_src.create(
            target_path=vault_path,
            master_passphrase=vpp,
            gpg_passphrase=gpp,
            fingerprints=[fp],
        )

    vault_svc_dst = VaultService(gpg=dest_gpg, audit=dest_audit)
    with SecureBytes.from_bytes(_VAULT_PASSPHRASE) as vpp:
        vault_svc_dst.import_keys(source_path=vault_path, master_passphrase=vpp)

    dest_msg_svc = MessageService(gpg=dest_gpg, audit=dest_audit)
    encrypt_result = dest_msg_svc.encrypt(b"secret for charlie", recipient_fingerprints=[fp], always_trust=True)
    assert "-----BEGIN PGP MESSAGE-----" in encrypt_result.armored_ciphertext
