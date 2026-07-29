"""End-to-end tests for vaults with a second, key-based unlock method.

These use an ordinary local GPG key as the unlock key. That exercises exactly
the code path a YubiKey takes: the vault's file key is wrapped into an OpenPGP
message addressed to the key, and opening the vault means asking GnuPG to
decrypt that message. The only difference on real hardware is where GnuPG finds
the private key and that the credential handed to `--passphrase-fd` is the card
PIN rather than a key passphrase — so everything below this line is identical.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from gpg_meister.models.key_info import KeyAlgorithm
from gpg_meister.models.vault import VAULT_FORMAT_VERSION, VAULT_FORMAT_VERSION_SLOTS
from gpg_meister.security.errors import DecryptionError
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.services.vault_service import VaultService, VaultServiceError
from gpg_meister.storage.audit_log import AuditLog

pytestmark = pytest.mark.integration

MASTER = b"master vault passphrase"
KEY_PASSPHRASE = b"correct horse battery staple"
UNLOCK_PASSPHRASE = b"token pin stand-in 4711"


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.log")


@pytest.fixture
def vault_service(isolated_gpg: GPGService, audit: AuditLog) -> VaultService:
    return VaultService(gpg=isolated_gpg, audit=audit)


def _make_key(service: GPGService, *, email: str, passphrase: bytes) -> str:
    with SecureBytes.from_bytes(passphrase) as pw:
        return service.generate_key(
            name="Alice",
            email=email,
            algorithm=KeyAlgorithm.EDDSA,
            length=255,
            expiry="2y",
            passphrase=pw,
        )


def _create_vault(
    vault_service: VaultService,
    target: Path,
    *,
    backup_fp: str,
    unlock_fps: list[str],
) -> None:
    with (
        SecureBytes.from_bytes(MASTER) as master,
        SecureBytes.from_bytes(KEY_PASSPHRASE) as gpgpw,
    ):
        vault_service.create(
            target_path=target,
            master_passphrase=master,
            gpg_passphrases={backup_fp: gpgpw},
            fingerprints=[backup_fp],
            description="token-protected backup",
            unlock_key_fingerprints=unlock_fps,
        )


@pytest.fixture
def token_vault(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService
) -> tuple[Path, str, str]:
    """A vault openable by the master passphrase *or* by the unlock key."""
    backup_fp = _make_key(isolated_gpg, email="alice@example.org", passphrase=KEY_PASSPHRASE)
    unlock_fp = _make_key(isolated_gpg, email="token@example.org", passphrase=UNLOCK_PASSPHRASE)
    target = tmp_path / "token.gpgvault"
    _create_vault(vault_service, target, backup_fp=backup_fp, unlock_fps=[unlock_fp])
    return target, backup_fp, unlock_fp


def test_vault_without_unlock_keys_stays_on_format_version_2(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService
) -> None:
    fp = _make_key(isolated_gpg, email="alice@example.org", passphrase=KEY_PASSPHRASE)
    target = tmp_path / "plain.gpgvault"

    _create_vault(vault_service, target, backup_fp=fp, unlock_fps=[])

    assert target.read_bytes()[4] == VAULT_FORMAT_VERSION
    assert vault_service.unlock_info(target).accepts_smartcard is False


def test_unlock_info_advertises_the_key_without_any_credential(
    token_vault: tuple[Path, str, str], vault_service: VaultService
) -> None:
    target, _backup_fp, unlock_fp = token_vault

    info = vault_service.unlock_info(target)

    assert info.version == VAULT_FORMAT_VERSION_SLOTS
    assert info.accepts_passphrase
    assert info.accepts_smartcard
    assert [slot.fingerprint for slot in info.smartcard_slots] == [unlock_fp]
    assert info.smartcard_slots[0].label


def test_vault_opens_with_the_token_credential(
    token_vault: tuple[Path, str, str], vault_service: VaultService
) -> None:
    target, backup_fp, _unlock_fp = token_vault

    with SecureBytes.from_bytes(UNLOCK_PASSPHRASE) as pin:
        preview = vault_service.preview(source_path=target, smartcard_pin=pin)

    assert preview.description == "token-protected backup"
    assert [key.fingerprint for key in preview.keys] == [backup_fp]


def test_master_passphrase_keeps_working_alongside_the_token(
    token_vault: tuple[Path, str, str], vault_service: VaultService
) -> None:
    """Losing the token must never orphan the backup."""
    target, backup_fp, _unlock_fp = token_vault

    with SecureBytes.from_bytes(MASTER) as master:
        preview = vault_service.preview(source_path=target, master_passphrase=master)

    assert [key.fingerprint for key in preview.keys] == [backup_fp]


def test_wrong_token_credential_is_rejected(
    token_vault: tuple[Path, str, str], vault_service: VaultService
) -> None:
    target, _backup_fp, _unlock_fp = token_vault

    with SecureBytes.from_bytes(b"wrong pin") as pin, pytest.raises(Exception) as excinfo:
        vault_service.preview(source_path=target, smartcard_pin=pin)

    assert not isinstance(excinfo.value, AssertionError)


def test_wrong_master_passphrase_is_rejected_on_a_slot_vault(
    token_vault: tuple[Path, str, str], vault_service: VaultService
) -> None:
    target, _backup_fp, _unlock_fp = token_vault

    with SecureBytes.from_bytes(b"not the master") as master, pytest.raises(DecryptionError):
        vault_service.preview(source_path=target, master_passphrase=master)


def test_import_from_a_token_vault_into_a_fresh_keyring(
    token_vault: tuple[Path, str, str], vault_service: VaultService
) -> None:
    target, backup_fp, _unlock_fp = token_vault

    with SecureBytes.from_bytes(UNLOCK_PASSPHRASE) as pin:
        imported = vault_service.import_keys(source_path=target, smartcard_pin=pin)

    assert imported == [backup_fp]


def test_opening_a_passphrase_only_vault_with_a_pin_is_refused(
    tmp_path: Path, isolated_gpg: GPGService, vault_service: VaultService
) -> None:
    fp = _make_key(isolated_gpg, email="alice@example.org", passphrase=KEY_PASSPHRASE)
    target = tmp_path / "plain.gpgvault"
    _create_vault(vault_service, target, backup_fp=fp, unlock_fps=[])

    with SecureBytes.from_bytes(b"1234") as pin, pytest.raises(VaultServiceError):
        vault_service.preview(source_path=target, smartcard_pin=pin)


def test_open_without_any_credential_is_refused(
    token_vault: tuple[Path, str, str], vault_service: VaultService
) -> None:
    target, _backup_fp, _unlock_fp = token_vault

    with pytest.raises(VaultServiceError):
        vault_service.preview(source_path=target)


def test_tampering_with_a_key_slot_breaks_the_vault(
    token_vault: tuple[Path, str, str], vault_service: VaultService
) -> None:
    """The header is the AEAD's associated data, so slots are tamper-evident.

    The token slot is edited but the vault is opened with the *passphrase* slot,
    which is untouched — so nothing but the payload's associated-data binding can
    notice the change. The edit also keeps the header length byte-for-byte
    identical, so the frame still parses and the tag is the only line of defence.
    """
    target, _backup_fp, _unlock_fp = token_vault
    raw = bytearray(target.read_bytes())
    marker = raw.rfind(b'"wrapped_key_b64":"')
    assert marker > 0
    victim = marker + len(b'"wrapped_key_b64":"')
    raw[victim] = ord("A") if raw[victim] != ord("A") else ord("B")
    target.write_bytes(bytes(raw))

    with SecureBytes.from_bytes(MASTER) as master, pytest.raises(DecryptionError):
        vault_service.preview(source_path=target, master_passphrase=master, skip_checksum=True)
