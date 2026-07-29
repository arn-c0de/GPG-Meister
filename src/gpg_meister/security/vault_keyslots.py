"""Key-slot wrapping for version 3 vaults.

A v2 vault encrypts its payload with a key derived straight from the master
passphrase, so the passphrase is the only way in. A v3 vault encrypts its
payload with a *random* file key and stores one wrapped copy of that key per
unlock method:

- a passphrase slot — the file key sealed with AEAD under ``Argon2id(passphrase)``,
- an OpenPGP slot — the file key sealed to a GPG key, which for a smartcard key
  means "openable only with the token present and its PIN entered".

Only the passphrase side lives here; wrapping to a GPG key needs the GPG
subprocess and therefore sits in ``services.vault_service``.

Every slot yields the *same* file key, so adding an unlock method never
re-encrypts the payload — and never weakens it below the strength of its weakest
slot, which is why the UI keeps the master passphrase mandatory.
"""

from __future__ import annotations

import base64
import secrets

from gpg_meister.models.kdf_params import KDFAlgorithm, KDFParams
from gpg_meister.models.vault import (
    VAULT_FORMAT_TAG,
    CipherAlgorithm,
    KDFFields,
    VaultKeySlot,
    VaultSlotType,
)
from gpg_meister.security.aead import KEY_LEN, generate_nonce
from gpg_meister.security.aead import decrypt as aead_decrypt
from gpg_meister.security.aead import encrypt as aead_encrypt
from gpg_meister.security.kdf import derive_key, generate_salt
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object

FILE_KEY_LEN = KEY_LEN


def slot_associated_data(slot_type: VaultSlotType) -> bytes:
    """Domain separator bound into a slot's AEAD tag.

    The outer payload AEAD already authenticates the whole header (slots
    included), so this only has to stop a wrapped key from being replayed into a
    slot of a different kind.
    """
    return f"{VAULT_FORMAT_TAG}:slot:{slot_type.value}".encode()


def generate_file_key() -> SecureBytes:
    """A fresh random payload key, held in a wiped-on-close buffer."""
    raw = secrets.token_bytes(FILE_KEY_LEN)
    try:
        return SecureBytes.from_bytes(raw)
    finally:
        _zero_bytes_object(raw)


def wrap_with_passphrase(
    file_key: SecureBytes,
    passphrase: SecureBytes,
    *,
    params: KDFParams,
    cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305,
) -> VaultKeySlot:
    """Seal ``file_key`` under a passphrase-derived key and return the slot."""
    salt = generate_salt(params.salt_len)
    nonce = generate_nonce()
    with derive_key(passphrase, salt, params) as slot_key:
        wrapped = aead_encrypt(
            plaintext=file_key.view(),
            key=slot_key,
            nonce=nonce,
            associated_data=slot_associated_data(VaultSlotType.PASSPHRASE),
            cipher=cipher,
        )
    return VaultKeySlot(
        type=VaultSlotType.PASSPHRASE,
        wrapped_key_b64=base64.b64encode(wrapped).decode("ascii"),
        kdf=KDFFields(
            algorithm=KDFAlgorithm.ARGON2ID,
            salt_b64=base64.b64encode(salt).decode("ascii"),
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
        ),
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        label="Master passphrase",
    )


def unwrap_with_passphrase(
    slot: VaultKeySlot,
    passphrase: SecureBytes,
    *,
    params: KDFParams,
    cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305,
) -> SecureBytes:
    """Recover the file key from a passphrase slot.

    Raises :class:`gpg_meister.security.errors.DecryptionError` when the
    passphrase is wrong or the slot was tampered with. ``params`` is passed in
    (rather than read from the slot) so the caller can enforce the import safety
    limits on untrusted vault headers first.
    """
    if slot.type is not VaultSlotType.PASSPHRASE or slot.kdf is None:
        raise ValueError("not a passphrase key slot")

    with derive_key(passphrase, slot.kdf.salt, params) as slot_key:
        raw = aead_decrypt(
            ciphertext=slot.wrapped_key,
            key=slot_key,
            nonce=slot.nonce,
            associated_data=slot_associated_data(VaultSlotType.PASSPHRASE),
            cipher=cipher,
        )
    return file_key_from_bytes(raw)


def file_key_from_bytes(raw: bytes) -> SecureBytes:
    """Move an unwrapped file key into a secure buffer and wipe the source.

    Shared by the passphrase and the OpenPGP unwrap paths so the length check
    and the wipe of the transient ``bytes`` copy happen in exactly one place.
    """
    try:
        if len(raw) != FILE_KEY_LEN:
            raise ValueError("unwrapped vault key has the wrong length")
        return SecureBytes.from_bytes(raw)
    finally:
        _zero_bytes_object(raw)


def openpgp_slot(wrapped: bytes, *, fingerprint: str, label: str = "") -> VaultKeySlot:
    """Build the slot record for a file key already sealed to a GPG key."""
    return VaultKeySlot(
        type=VaultSlotType.OPENPGP,
        wrapped_key_b64=base64.b64encode(wrapped).decode("ascii"),
        fingerprint=fingerprint,
        label=label,
    )
