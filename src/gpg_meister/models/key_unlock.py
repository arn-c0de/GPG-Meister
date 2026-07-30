"""Unlock methods for a local GPG key: how its passphrase is handed back.

A GPG key has exactly *one* passphrase, which is the whole problem this module
exists to solve. If a hardware token derived that passphrase directly, then
enrolling a second token, keeping an emergency way in, or retiring a lost token
would each mean changing the key's passphrase — a destructive rewrite of the
secret key for what should be a bookkeeping change.

So the passphrase is not derived from anything. It is a *random secret*, and
each unlock method stores its own wrapped copy of it:

- a **passphrase slot** — the secret sealed with AEAD under ``Argon2id(passphrase)``,
- a **FIDO slot** — the secret sealed under a key the token derives from its
  ``prf`` / ``hmac-secret`` extension, which no one can reproduce without that
  physical token.

Every slot yields the same secret, so adding or removing an unlock method never
touches the GPG key itself. This mirrors what version 3 vaults already do with
their file key (``models.vault``); the shapes are deliberately parallel, because
it is the same idea applied to a different thing.

Nothing here is a secret on its own: a credential id and a PRF salt are useless
without the token, and the wrapped secret is AEAD-protected. What they *are* is
irreplaceable — losing them locks the key as surely as losing the token does,
which is why an emergency passphrase slot is the default.
"""

from __future__ import annotations

import base64
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gpg_meister.models.vault import NONCE_LEN, KDFFields

# One key may reasonably carry an emergency passphrase plus a handful of tokens.
# The bound exists so a corrupted store cannot make unlocking unbounded work.
MAX_KEY_UNLOCK_SLOTS = 8
MAX_UNLOCK_SLOT_LABEL_LENGTH = 96

# The wrapped secret is a base64 passphrase (44 bytes) plus an AEAD tag; the
# ceiling is generous enough for that and small enough to reject nonsense.
MAX_WRAPPED_SECRET_LENGTH = 256

# CTAP2 allows credential ids up to 1023 bytes; the tokens seen in practice use
# 64. The PRF salt is fixed at 32 bytes because that is what we always generate.
MAX_CREDENTIAL_ID_LENGTH = 1023
PRF_SALT_LEN = 32

# Domain separator bound into each slot's AEAD tag, so a wrapped secret cannot
# be replayed from one slot kind into another, nor from a vault key slot.
UNLOCK_FORMAT_TAG = "gpg-meister-key-unlock/1"


class UnlockSlotType(StrEnum):
    """How a slot hands back the key's passphrase."""

    PASSPHRASE = "passphrase"  # noqa: S105 - a slot kind, not a credential
    FIDO = "fido"


class FidoCredential(BaseModel):
    """What identifies one token binding — none of it secret, all of it required.

    ``resident`` records whether the token stores the credential itself. A
    resident credential survives the loss of this record; a non-resident one
    exists *only* here, and losing this row locks the key.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    credential_id_b64: str
    salt_b64: str
    rp_id: str = Field(min_length=1, max_length=253)
    resident: bool = True
    # Whether the token was told to verify the user (FIDO2 PIN) rather than
    # settle for a touch. Recorded so unlocking asks for exactly what enrolment
    # required, instead of discovering the mismatch from a CTAP error.
    user_verification: bool = True
    label: str = Field(default="", max_length=MAX_UNLOCK_SLOT_LABEL_LENGTH)

    @field_validator("credential_id_b64")
    @classmethod
    def _validate_credential_id(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("credential_id_b64 must be valid base64") from exc
        if not raw:
            raise ValueError("credential id must not be empty")
        if len(raw) > MAX_CREDENTIAL_ID_LENGTH:
            raise ValueError("credential id is too large")
        return value

    @field_validator("salt_b64")
    @classmethod
    def _validate_salt(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("salt_b64 must be valid base64") from exc
        if len(raw) != PRF_SALT_LEN:
            raise ValueError(f"PRF salt must decode to {PRF_SALT_LEN} bytes")
        return value

    @property
    def credential_id(self) -> bytes:
        return base64.b64decode(self.credential_id_b64, validate=True)

    @property
    def salt(self) -> bytes:
        return base64.b64decode(self.salt_b64, validate=True)


class KeyUnlockSlot(BaseModel):
    """One way to recover a key's passphrase: a wrapped copy of the secret.

    ``PASSPHRASE`` slots carry their own KDF parameters and salt. ``FIDO`` slots
    carry the token binding instead and need no KDF, because the token's PRF
    output is already a uniformly random 32-byte key.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: UnlockSlotType
    wrapped_secret_b64: str
    nonce_b64: str
    kdf: KDFFields | None = None
    fido: FidoCredential | None = None
    label: str = Field(default="", max_length=MAX_UNLOCK_SLOT_LABEL_LENGTH)

    @field_validator("wrapped_secret_b64")
    @classmethod
    def _validate_wrapped(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("wrapped_secret_b64 must be valid base64") from exc
        if not raw:
            raise ValueError("wrapped secret must not be empty")
        if len(raw) > MAX_WRAPPED_SECRET_LENGTH:
            raise ValueError("wrapped secret is too large")
        return value

    @field_validator("nonce_b64")
    @classmethod
    def _validate_nonce(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("nonce_b64 must be valid base64") from exc
        if len(raw) != NONCE_LEN:
            raise ValueError(f"nonce must decode to {NONCE_LEN} bytes")
        return value

    @model_validator(mode="after")
    def _validate_slot_shape(self) -> KeyUnlockSlot:
        if self.type is UnlockSlotType.PASSPHRASE:
            if self.kdf is None:
                raise ValueError("a passphrase slot needs KDF parameters")
            if self.fido is not None:
                raise ValueError("a passphrase slot must not carry a token binding")
        else:
            if self.fido is None:
                raise ValueError("a FIDO slot needs its token binding")
            if self.kdf is not None:
                raise ValueError("a FIDO slot must not carry KDF parameters")
        return self

    @property
    def wrapped_secret(self) -> bytes:
        return base64.b64decode(self.wrapped_secret_b64, validate=True)

    @property
    def nonce(self) -> bytes:
        return base64.b64decode(self.nonce_b64, validate=True)


def slots_of(
    slots: tuple[KeyUnlockSlot, ...], slot_type: UnlockSlotType
) -> tuple[KeyUnlockSlot, ...]:
    return tuple(slot for slot in slots if slot.type is slot_type)


def has_emergency_passphrase(slots: tuple[KeyUnlockSlot, ...]) -> bool:
    """Whether anything but a token can still open this key.

    The UI keeps this true unless the user explicitly accepts a token-only key,
    the same rule token-only vaults already follow.
    """
    return bool(slots_of(slots, UnlockSlotType.PASSPHRASE))
