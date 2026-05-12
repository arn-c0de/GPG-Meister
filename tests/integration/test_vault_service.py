"""End-to-end vault tests: real GPG keyring + real vault file on disk.

The vault service depends on the GPG service, so all tests in this module run
through the `isolated_gpg` fixture (which itself skips if no GnuPG is present).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from gpg_meister.models.key_info import KeyAlgorithm
from gpg_meister.security.errors import DecryptionError, VaultFormatError
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.gpg_service import GPGService, GPGServiceConfig
from gpg_meister.services.vault_service import (
    VaultService,
    VaultServiceError,
)
from gpg_meister.storage.audit_log import AuditLog

pytestmark = pytest.mark.integration


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.log")


@pytest.fixture
def vault_service(isolated_gpg: GPGService, audit: AuditLog) -> VaultService:
    return VaultService(gpg=isolated_gpg, audit=audit)


def _make_key(service: GPGService, *, email: str = "alice@example.org") -> str:
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        return service.generate_key(
            name="Alice",
            email=email,
            algorithm=KeyAlgorithm.EDDSA,
            length=255,
            expiry="2y",
            passphrase=pw,
        )


def test_create_writes_vault_and_sidecar(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService
) -> None:
    fp = _make_key(isolated_gpg)
    target = tmp_path / "alice.gpgvault"

    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        SecureBytes.from_bytes(b"correct horse battery staple") as gpgpw,
    ):
        result = vault_service.create(
            target_path=target,
            master_passphrase=master,
            gpg_passphrase=gpgpw,
            fingerprints=[fp],
            description="dev",
        )

    assert target.exists()
    assert target.with_name(target.name + ".sha256").exists()
    assert result.key_count == 1
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
    assert result.sha256 == actual


def test_create_and_preview_roundtrip(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService
) -> None:
    fp = _make_key(isolated_gpg)
    target = tmp_path / "alice.gpgvault"

    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        SecureBytes.from_bytes(b"correct horse battery staple") as gpgpw,
    ):
        vault_service.create(
            target_path=target,
            master_passphrase=master,
            gpg_passphrase=gpgpw,
            fingerprints=[fp],
            description="dev",
        )

    with SecureBytes.from_bytes(b"master vault passphrase") as master:
        preview = vault_service.preview(source_path=target, master_passphrase=master)

    assert preview.description == "dev"
    assert len(preview.keys) == 1
    assert preview.keys[0].fingerprint == fp
    assert preview.keys[0].has_private_key


def test_import_into_separate_keyring(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService, audit: AuditLog
) -> None:
    fp = _make_key(isolated_gpg)
    target = tmp_path / "alice.gpgvault"

    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        SecureBytes.from_bytes(b"correct horse battery staple") as gpgpw,
    ):
        vault_service.create(
            target_path=target,
            master_passphrase=master,
            gpg_passphrase=gpgpw,
            fingerprints=[fp],
        )

    # Second isolated keyring with its own audit channel.
    other_home = tmp_path / "other-gnupg"
    other_home.mkdir(mode=0o700)
    other_gpg = GPGService(
        GPGServiceConfig(binary_path=isolated_gpg.config.binary_path, home_dir=other_home)
    )
    other_audit = AuditLog(tmp_path / "other-audit.log")
    other_vault = VaultService(gpg=other_gpg, audit=other_audit)

    with SecureBytes.from_bytes(b"master vault passphrase") as master:
        imported = other_vault.import_keys(
            source_path=target, master_passphrase=master
        )

    assert fp in imported
    assert any(k.fingerprint == fp for k in other_gpg.list_keys())


def test_wrong_master_passphrase_raises_decryption_error(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService
) -> None:
    fp = _make_key(isolated_gpg)
    target = tmp_path / "alice.gpgvault"

    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        SecureBytes.from_bytes(b"correct horse battery staple") as gpgpw,
    ):
        vault_service.create(
            target_path=target,
            master_passphrase=master,
            gpg_passphrase=gpgpw,
            fingerprints=[fp],
        )

    with SecureBytes.from_bytes(b"wrong passphrase") as bad, pytest.raises(DecryptionError):
        vault_service.preview(source_path=target, master_passphrase=bad)


def test_header_tampering_detected_via_aad(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService
) -> None:
    fp = _make_key(isolated_gpg)
    target = tmp_path / "alice.gpgvault"

    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        SecureBytes.from_bytes(b"correct horse battery staple") as gpgpw,
    ):
        vault_service.create(
            target_path=target,
            master_passphrase=master,
            gpg_passphrase=gpgpw,
            fingerprints=[fp],
        )

    # Flip a byte inside the header JSON window. We locate it by scanning for the
    # opening brace of the JSON object.
    raw = bytearray(target.read_bytes())
    brace = raw.index(b"{")
    raw[brace + 1] ^= 0x01
    target.write_bytes(bytes(raw))

    # Either VaultFormatError (header re-parse breaks) or DecryptionError
    # (AAD mismatch) — both indicate detection.
    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        pytest.raises((DecryptionError, VaultFormatError)),
    ):
        vault_service.preview(source_path=target, master_passphrase=master)


def test_ciphertext_tampering_detected(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService
) -> None:
    fp = _make_key(isolated_gpg)
    target = tmp_path / "alice.gpgvault"

    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        SecureBytes.from_bytes(b"correct horse battery staple") as gpgpw,
    ):
        vault_service.create(
            target_path=target,
            master_passphrase=master,
            gpg_passphrase=gpgpw,
            fingerprints=[fp],
        )

    raw = bytearray(target.read_bytes())
    raw[-1] ^= 0xFF  # flip the last byte (inside the AEAD tag)
    target.write_bytes(bytes(raw))

    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        pytest.raises(DecryptionError),
    ):
        vault_service.preview(source_path=target, master_passphrase=master)


def test_corrupted_sidecar_is_detected(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService
) -> None:
    fp = _make_key(isolated_gpg)
    target = tmp_path / "alice.gpgvault"

    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        SecureBytes.from_bytes(b"correct horse battery staple") as gpgpw,
    ):
        vault_service.create(
            target_path=target,
            master_passphrase=master,
            gpg_passphrase=gpgpw,
            fingerprints=[fp],
        )

    sidecar = target.with_name(target.name + ".sha256")
    sidecar.write_text("0" * 64 + f"  {target.name}\n", encoding="utf-8")

    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        pytest.raises(VaultServiceError, match="checksum"),
    ):
        vault_service.preview(source_path=target, master_passphrase=master)


def test_audit_records_vault_creation(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService, audit: AuditLog
) -> None:
    import json

    fp = _make_key(isolated_gpg)
    target = tmp_path / "alice.gpgvault"

    with (
        SecureBytes.from_bytes(b"master vault passphrase") as master,
        SecureBytes.from_bytes(b"correct horse battery staple") as gpgpw,
    ):
        vault_service.create(
            target_path=target,
            master_passphrase=master,
            gpg_passphrase=gpgpw,
            fingerprints=[fp],
        )

    audit.close()
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    events = [json.loads(line)["event"] for line in lines if line]
    assert "vault_created" in events
    assert "key_exported_private" in events
