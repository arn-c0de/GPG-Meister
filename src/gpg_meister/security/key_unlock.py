"""Wrapping a GPG key's passphrase for each of its unlock methods.

The passphrase is a random secret (see ``models.key_unlock`` for why it is not
derived from anything), and this module is where it is created, sealed, and
recovered. Two kinds of slot:

- **passphrase** — sealed under ``Argon2id(user passphrase)``, exactly as a v3
  vault seals its file key,
- **FIDO** — sealed under the 32 bytes a hardware token derives through its
  ``prf`` extension. That output is already uniformly random, so it is used as
  the AEAD key directly; stretching it with a KDF would add cost and no
  strength, and there is no low-entropy input here to stretch.

The GPG side of the passphrase is deliberately plain: GnuPG reads it from a pipe
up to a newline, so the secret is base64 text rather than raw bytes. Raw bytes
would eventually contain ``0x0a`` and silently truncate the passphrase — a bug
that would only surface for some keys, long after they were created.
"""

from __future__ import annotations

import base64
import secrets

from gpg_meister.models.kdf_params import KDFAlgorithm, KDFParams
from gpg_meister.models.key_unlock import (
    UNLOCK_FORMAT_TAG,
    FidoCredential,
    KeyUnlockSlot,
    UnlockSlotType,
)
from gpg_meister.models.vault import CipherAlgorithm, KDFFields
from gpg_meister.security.aead import KEY_LEN, generate_nonce
from gpg_meister.security.aead import decrypt as aead_decrypt
from gpg_meister.security.aead import encrypt as aead_encrypt
from gpg_meister.security.errors import DecryptionError
from gpg_meister.security.kdf import derive_key, generate_salt
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object

# Entropy behind the generated passphrase, before base64 encoding.
KEY_SECRET_RAW_LEN = 32
# What that becomes as text, and therefore the length GnuPG sees.
KEY_SECRET_TEXT_LEN = 44

# A slot may also wrap a passphrase the user already chose, which is what lets
# an existing key be bound to a token without rewriting the key. So the sealed
# secret is bounded rather than fixed-length; the ceiling stays below
# MAX_WRAPPED_SECRET_LENGTH once the AEAD tag is added.
MAX_KEY_SECRET_LEN = 200

# Bytes that would break the passphrase on its way to GnuPG: NUL terminates C
# string paths inside pinentry helpers, CR/LF close the --passphrase-fd line
# early. gpg_service rejects them too; catching them here means a bad secret is
# refused before it is sealed, instead of at some later unlock.
_FRAMING_BYTES = (0x00, 0x0A, 0x0D)

# The token's PRF output is used as an AEAD key as-is, so it has to be exactly
# the AEAD key length. CTAP2 hmac-secret/prf always returns 32 bytes.
TOKEN_SECRET_LEN = KEY_LEN


def slot_associated_data(slot_type: UnlockSlotType) -> bytes:
    """Domain separator bound into a slot's AEAD tag.

    Stops a wrapped secret from being replayed into a slot of a different kind,
    and — because the tag names this format — from being confused with a vault
    key slot, whose wrapped value is the same size and shape.
    """
    return f"{UNLOCK_FORMAT_TAG}:slot:{slot_type.value}".encode()


def generate_key_secret() -> SecureBytes:
    """A fresh random passphrase for a GPG key, as ASCII text in a wiped buffer."""
    raw = secrets.token_bytes(KEY_SECRET_RAW_LEN)
    try:
        text = base64.b64encode(raw)
        try:
            return SecureBytes.from_bytes(text)
        finally:
            _zero_bytes_object(text)
    finally:
        _zero_bytes_object(raw)


def check_secret(secret: SecureBytes) -> None:
    """Reject a passphrase that could not survive the trip to GnuPG."""
    if not 0 < len(secret) <= MAX_KEY_SECRET_LEN:
        raise ValueError(f"a key secret must be 1 to {MAX_KEY_SECRET_LEN} bytes")
    view = secret.view()
    if any(byte in _FRAMING_BYTES for byte in view):
        raise ValueError("a key secret must not contain NUL or newline characters")


def _secret_from_bytes(raw: bytes) -> SecureBytes:
    """Move an unwrapped passphrase into a secure buffer and wipe the source."""
    try:
        if not 0 < len(raw) <= MAX_KEY_SECRET_LEN:
            raise DecryptionError("unwrapped key secret has an implausible length")
        return SecureBytes.from_bytes(raw)
    finally:
        _zero_bytes_object(raw)


def wrap_with_passphrase(
    secret: SecureBytes,
    passphrase: SecureBytes,
    *,
    params: KDFParams,
    label: str = "Emergency passphrase",
    cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305,
) -> KeyUnlockSlot:
    """Seal the key secret under a user passphrase and return the slot."""
    check_secret(secret)
    salt = generate_salt(params.salt_len)
    nonce = generate_nonce()
    with derive_key(passphrase, salt, params) as slot_key:
        wrapped = aead_encrypt(
            plaintext=secret.view(),
            key=slot_key,
            nonce=nonce,
            associated_data=slot_associated_data(UnlockSlotType.PASSPHRASE),
            cipher=cipher,
        )
    return KeyUnlockSlot(
        type=UnlockSlotType.PASSPHRASE,
        wrapped_secret_b64=base64.b64encode(wrapped).decode("ascii"),
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        kdf=KDFFields(
            algorithm=KDFAlgorithm.ARGON2ID,
            salt_b64=base64.b64encode(salt).decode("ascii"),
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
        ),
        label=label,
    )


def unwrap_with_passphrase(
    slot: KeyUnlockSlot,
    passphrase: SecureBytes,
    *,
    params: KDFParams,
    cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305,
) -> SecureBytes:
    """Recover the key secret from a passphrase slot.

    Raises :class:`DecryptionError` when the passphrase is wrong or the slot was
    tampered with — the AEAD tag makes those indistinguishable, which is the
    point.
    """
    if slot.type is not UnlockSlotType.PASSPHRASE or slot.kdf is None:
        raise ValueError("not a passphrase unlock slot")
    with derive_key(passphrase, slot.kdf.salt, params) as slot_key:
        raw = aead_decrypt(
            ciphertext=slot.wrapped_secret,
            key=slot_key,
            nonce=slot.nonce,
            associated_data=slot_associated_data(UnlockSlotType.PASSPHRASE),
            cipher=cipher,
        )
    return _secret_from_bytes(raw)


def _check_token_secret(token_secret: SecureBytes) -> None:
    if len(token_secret) != TOKEN_SECRET_LEN:
        raise ValueError(f"a token secret must be exactly {TOKEN_SECRET_LEN} bytes")


def wrap_with_token(
    secret: SecureBytes,
    token_secret: SecureBytes,
    *,
    credential: FidoCredential,
    cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305,
) -> KeyUnlockSlot:
    """Seal the key secret under a token's PRF output and return the slot.

    ``token_secret`` is used as the AEAD key unchanged: it is 32 uniformly
    random bytes that only this token can reproduce, so there is nothing for a
    KDF to strengthen.
    """
    check_secret(secret)
    _check_token_secret(token_secret)
    nonce = generate_nonce()
    wrapped = aead_encrypt(
        plaintext=secret.view(),
        key=token_secret,
        nonce=nonce,
        associated_data=slot_associated_data(UnlockSlotType.FIDO),
        cipher=cipher,
    )
    return KeyUnlockSlot(
        type=UnlockSlotType.FIDO,
        wrapped_secret_b64=base64.b64encode(wrapped).decode("ascii"),
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        fido=credential,
        label=credential.label,
    )


def unwrap_with_token(
    slot: KeyUnlockSlot,
    token_secret: SecureBytes,
    *,
    cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305,
) -> SecureBytes:
    """Recover the key secret from a FIDO slot using the token's PRF output."""
    if slot.type is not UnlockSlotType.FIDO or slot.fido is None:
        raise ValueError("not a FIDO unlock slot")
    _check_token_secret(token_secret)
    raw = aead_decrypt(
        ciphertext=slot.wrapped_secret,
        key=token_secret,
        nonce=slot.nonce,
        associated_data=slot_associated_data(UnlockSlotType.FIDO),
        cipher=cipher,
    )
    return _secret_from_bytes(raw)
