"""Vault key slots: wrapping, header shape, and v2 byte compatibility."""

from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

from gpg_meister.models.kdf_params import KDFAlgorithm, KDFParams
from gpg_meister.models.vault import (
    VAULT_FORMAT_VERSION,
    VAULT_FORMAT_VERSION_SLOTS,
    CipherAlgorithm,
    CipherParams,
    KDFFields,
    VaultHeader,
    VaultKeySlot,
    VaultSlotType,
)
from gpg_meister.security.aead import generate_nonce
from gpg_meister.security.errors import DecryptionError
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.security.vault_format import header_to_canonical_json
from gpg_meister.security.vault_format import pack as vault_pack
from gpg_meister.security.vault_format import unpack as vault_unpack
from gpg_meister.security.vault_keyslots import (
    FILE_KEY_LEN,
    generate_file_key,
    openpgp_slot,
    unwrap_with_passphrase,
    wrap_with_passphrase,
)

FPR = "A" * 40

# The cheapest parameters the policy floor allows, so these tests stay fast;
# production vaults use high_memory_params().
FAST_PARAMS = KDFParams(
    algorithm=KDFAlgorithm.ARGON2ID,
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def _kdf_fields() -> KDFFields:
    return KDFFields(
        algorithm=KDFAlgorithm.ARGON2ID,
        salt_b64=base64.b64encode(b"0123456789abcdef").decode("ascii"),
        time_cost=FAST_PARAMS.time_cost,
        memory_cost=FAST_PARAMS.memory_cost,
        parallelism=FAST_PARAMS.parallelism,
        hash_len=FAST_PARAMS.hash_len,
    )


def _cipher() -> CipherParams:
    return CipherParams(
        algorithm=CipherAlgorithm.CHACHA20_POLY1305,
        nonce_b64=base64.b64encode(generate_nonce()).decode("ascii"),
    )


# ------------------------------------------------------------- wrapping


def test_passphrase_slot_round_trips_the_file_key() -> None:
    with generate_file_key() as file_key, SecureBytes.from_bytes(b"vault master pass") as pw:
        original = bytes(file_key.view())
        slot = wrap_with_passphrase(file_key, pw, params=FAST_PARAMS)

        with unwrap_with_passphrase(slot, pw, params=FAST_PARAMS) as recovered:
            assert bytes(recovered.view()) == original
            assert len(recovered) == FILE_KEY_LEN


def test_wrong_passphrase_does_not_yield_a_key() -> None:
    with generate_file_key() as file_key, SecureBytes.from_bytes(b"right pass") as pw:
        slot = wrap_with_passphrase(file_key, pw, params=FAST_PARAMS)

    with SecureBytes.from_bytes(b"wrong pass") as wrong, pytest.raises(DecryptionError):
        unwrap_with_passphrase(slot, wrong, params=FAST_PARAMS)


def test_wrapped_key_is_not_the_file_key_in_the_clear() -> None:
    with generate_file_key() as file_key, SecureBytes.from_bytes(b"vault master pass") as pw:
        original = bytes(file_key.view())
        slot = wrap_with_passphrase(file_key, pw, params=FAST_PARAMS)

    assert original not in slot.wrapped_key


def test_slot_of_the_other_type_is_rejected_by_unwrap() -> None:
    slot = openpgp_slot(b"-----BEGIN PGP MESSAGE-----", fingerprint=FPR, label="YubiKey 1")

    with SecureBytes.from_bytes(b"pass") as pw, pytest.raises(ValueError, match="passphrase"):
        unwrap_with_passphrase(slot, pw, params=FAST_PARAMS)


# ---------------------------------------------------------- slot shapes


def test_passphrase_slot_requires_kdf_and_nonce() -> None:
    with pytest.raises(ValidationError):
        VaultKeySlot(
            type=VaultSlotType.PASSPHRASE,
            wrapped_key_b64=base64.b64encode(b"x" * 48).decode("ascii"),
        )


def test_openpgp_slot_requires_a_fingerprint() -> None:
    with pytest.raises(ValidationError):
        VaultKeySlot(
            type=VaultSlotType.OPENPGP,
            wrapped_key_b64=base64.b64encode(b"x" * 48).decode("ascii"),
        )


def test_openpgp_slot_rejects_kdf_parameters() -> None:
    with pytest.raises(ValidationError):
        VaultKeySlot(
            type=VaultSlotType.OPENPGP,
            wrapped_key_b64=base64.b64encode(b"x" * 48).decode("ascii"),
            fingerprint=FPR,
            kdf=_kdf_fields(),
        )


def test_oversized_wrapped_key_is_rejected() -> None:
    with pytest.raises(ValidationError):
        openpgp_slot(b"x" * (17 * 1024), fingerprint=FPR)


# -------------------------------------------------------- header shapes


def test_version_2_header_must_not_carry_key_slots() -> None:
    with pytest.raises(ValidationError):
        VaultHeader(
            version=VAULT_FORMAT_VERSION,
            kdf=_kdf_fields(),
            cipher=_cipher(),
            key_slots=(openpgp_slot(b"msg", fingerprint=FPR),),
        )


def test_version_3_header_needs_at_least_one_slot() -> None:
    with pytest.raises(ValidationError):
        VaultHeader(version=VAULT_FORMAT_VERSION_SLOTS, cipher=_cipher())


def test_version_3_header_must_not_carry_a_top_level_kdf() -> None:
    with pytest.raises(ValidationError):
        VaultHeader(
            version=VAULT_FORMAT_VERSION_SLOTS,
            kdf=_kdf_fields(),
            cipher=_cipher(),
            key_slots=(openpgp_slot(b"msg", fingerprint=FPR),),
        )


def test_version_2_header_bytes_are_unchanged_by_the_new_field() -> None:
    """Key slots must not alter the AAD of vaults written before they existed."""
    header = VaultHeader(kdf=_kdf_fields(), cipher=_cipher())

    encoded = header_to_canonical_json(header).decode("utf-8")

    assert "key_slots" not in encoded
    assert encoded.startswith('{"cipher":')


def test_slot_header_round_trips_through_the_frame() -> None:
    slots = (openpgp_slot(b"-----BEGIN PGP MESSAGE-----", fingerprint=FPR, label="YubiKey 1"),)
    header = VaultHeader(
        version=VAULT_FORMAT_VERSION_SLOTS, cipher=_cipher(), key_slots=slots
    )

    frame, header_bytes = vault_pack(header, b"ciphertext-with-tag")
    unpacked = vault_unpack(frame)

    assert frame[4] == VAULT_FORMAT_VERSION_SLOTS
    assert unpacked.header_bytes == header_bytes
    assert unpacked.header.uses_key_slots
    assert unpacked.header.slots_of(VaultSlotType.OPENPGP)[0].fingerprint == FPR
    assert unpacked.header.slots_of(VaultSlotType.PASSPHRASE) == ()
