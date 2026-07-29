"""Vault domain models.

Header is the unencrypted, minimised metadata required to derive the vault key and
locate the AEAD nonce. Manifest is the encrypted payload — it contains the actual key
material and richer metadata (timestamps, app version, description).
"""

from __future__ import annotations

import base64
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gpg_meister.models.kdf_params import (
    MAX_SALT_LEN,
    MIN_SALT_LEN,
    HashLen,
    KDFAlgorithm,
    KDFParams,
    MemoryCost,
    Parallelism,
    TimeCost,
)
from gpg_meister.models.key_info import FINGERPRINT_LENGTH, normalise_fingerprint

VAULT_FORMAT_TAG = "GPGMEISTER_VAULT"
# Version 2: the AEAD key is derived straight from the master passphrase.
# Version 3: the AEAD key is random and wrapped once per unlock method ("key
# slot") — a passphrase slot plus one slot per smartcard/OpenPGP key. Vaults are
# only written as v3 when a second unlock method was requested, so a
# passphrase-only vault stays byte-compatible with older releases.
VAULT_FORMAT_VERSION = 2
VAULT_FORMAT_VERSION_SLOTS = 3
SUPPORTED_VAULT_VERSIONS = (VAULT_FORMAT_VERSION, VAULT_FORMAT_VERSION_SLOTS)
NONCE_LEN = 12
MAX_VAULT_KEY_SLOTS = 8
# A wrapped file key is 48 bytes for a passphrase slot; an armored PGP message
# holding 32 bytes is well under 4 KiB even for large RSA keys.
MAX_WRAPPED_KEY_LENGTH = 16 * 1024
MAX_VAULT_SLOT_LABEL_LENGTH = 128
MAX_VAULT_KEYS = 1024
MAX_VAULT_USER_IDS = 16
MAX_VAULT_USER_ID_LENGTH = 512
MAX_VAULT_DESCRIPTION_LENGTH = 4096
MAX_VAULT_CREATED_BY_LENGTH = 256
MAX_VAULT_ARMOR_LENGTH = 8 * 1024 * 1024  # 8 MB — accommodates large keyblocks with many certifications


class CipherAlgorithm(StrEnum):
    CHACHA20_POLY1305 = "chacha20-poly1305"
    AES_256_GCM = "aes-256-gcm"


class CipherParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: CipherAlgorithm
    nonce_b64: str

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

    @property
    def nonce(self) -> bytes:
        return base64.b64decode(self.nonce_b64, validate=True)


class KDFFields(BaseModel):
    """Header representation of KDFParams plus the per-vault salt.

    Bounds are enforced here so a forged vault header cannot request, e.g.,
    `memory_cost = 999_999_999` and force the host to allocate 1 TB during a
    decryption attempt. The same bounds also live on `KDFParams` so the policy is
    consistent across the trust boundary.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: KDFAlgorithm
    salt_b64: str
    time_cost: TimeCost
    memory_cost: MemoryCost
    parallelism: Parallelism
    hash_len: HashLen

    @field_validator("salt_b64")
    @classmethod
    def _validate_salt(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("salt_b64 must be valid base64") from exc
        if len(raw) < MIN_SALT_LEN or len(raw) > MAX_SALT_LEN:
            raise ValueError(
                f"salt must decode to between {MIN_SALT_LEN} and {MAX_SALT_LEN} bytes"
            )
        return value

    @property
    def salt(self) -> bytes:
        return base64.b64decode(self.salt_b64, validate=True)

    def to_params(self) -> KDFParams:
        return KDFParams(
            algorithm=self.algorithm,
            time_cost=self.time_cost,
            memory_cost=self.memory_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            salt_len=len(self.salt),
        )


class VaultSlotType(StrEnum):
    """How a key slot hands back the vault's file key."""

    PASSPHRASE = "passphrase"  # noqa: S105 - a slot kind, not a credential
    OPENPGP = "openpgp"


class VaultKeySlot(BaseModel):
    """One unlock method for a v3 vault: a wrapped copy of the file key.

    ``PASSPHRASE`` slots hold an AEAD-wrapped key with their own KDF salt and
    nonce. ``OPENPGP`` slots hold an armored PGP message addressed to a GPG key —
    for a smartcard key that message can only be opened with the token plugged
    in and its PIN entered, which is what makes a YubiKey a vault unlock method.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: VaultSlotType
    wrapped_key_b64: str
    kdf: KDFFields | None = None
    nonce_b64: str | None = None
    fingerprint: str | None = None
    label: str = Field(default="", max_length=MAX_VAULT_SLOT_LABEL_LENGTH)

    @field_validator("wrapped_key_b64")
    @classmethod
    def _validate_wrapped(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("wrapped_key_b64 must be valid base64") from exc
        if not raw:
            raise ValueError("wrapped key must not be empty")
        if len(raw) > MAX_WRAPPED_KEY_LENGTH:
            raise ValueError("wrapped key is too large")
        return value

    @field_validator("nonce_b64")
    @classmethod
    def _validate_nonce(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("nonce_b64 must be valid base64") from exc
        if len(raw) != NONCE_LEN:
            raise ValueError(f"nonce must decode to {NONCE_LEN} bytes")
        return value

    @field_validator("fingerprint")
    @classmethod
    def _validate_fingerprint(cls, value: str | None) -> str | None:
        return None if value is None else normalise_fingerprint(value)

    @model_validator(mode="after")
    def _validate_slot_shape(self) -> VaultKeySlot:
        if self.type is VaultSlotType.PASSPHRASE:
            if self.kdf is None or self.nonce_b64 is None:
                raise ValueError("a passphrase slot needs KDF parameters and a nonce")
            if self.fingerprint is not None:
                raise ValueError("a passphrase slot must not carry a key fingerprint")
        else:
            if self.fingerprint is None:
                raise ValueError("an OpenPGP slot needs the recipient fingerprint")
            if self.kdf is not None or self.nonce_b64 is not None:
                raise ValueError("an OpenPGP slot must not carry KDF parameters")
        return self

    @property
    def wrapped_key(self) -> bytes:
        return base64.b64decode(self.wrapped_key_b64, validate=True)

    @property
    def nonce(self) -> bytes:
        if self.nonce_b64 is None:
            raise ValueError("this slot has no nonce")
        return base64.b64decode(self.nonce_b64, validate=True)


class VaultHeader(BaseModel):
    """The unencrypted vault header. Bytes form is AAD-bound to the AEAD tag."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    format: str = Field(default=VAULT_FORMAT_TAG)
    version: int = Field(default=VAULT_FORMAT_VERSION)
    # v2 derives the AEAD key from the passphrase with these parameters; v3
    # leaves this unset and carries one wrapped key per slot instead. Fields that
    # are None are omitted from the canonical JSON, so a v2 header keeps exactly
    # the bytes it had before key slots existed.
    kdf: KDFFields | None = None
    cipher: CipherParams
    key_slots: tuple[VaultKeySlot, ...] | None = Field(default=None, max_length=MAX_VAULT_KEY_SLOTS)

    @field_validator("format")
    @classmethod
    def _validate_format(cls, value: str) -> str:
        if value != VAULT_FORMAT_TAG:
            raise ValueError(f"unknown vault format tag: {value!r}")
        return value

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: int) -> int:
        if value not in SUPPORTED_VAULT_VERSIONS:
            raise ValueError(f"unsupported vault version: {value}")
        return value

    @model_validator(mode="after")
    def _validate_version_shape(self) -> VaultHeader:
        if self.version == VAULT_FORMAT_VERSION:
            if self.kdf is None:
                raise ValueError("a version 2 vault header needs KDF parameters")
            if self.key_slots is not None:
                raise ValueError("key slots require vault version 3")
            return self
        if not self.key_slots:
            raise ValueError("a version 3 vault header needs at least one key slot")
        if self.kdf is not None:
            raise ValueError("a version 3 vault header derives no key from the header KDF")
        return self

    @property
    def uses_key_slots(self) -> bool:
        return bool(self.key_slots)

    def slots_of(self, slot_type: VaultSlotType) -> tuple[VaultKeySlot, ...]:
        return tuple(slot for slot in (self.key_slots or ()) if slot.type is slot_type)


class VaultKeyEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    fingerprint: str = Field(..., min_length=FINGERPRINT_LENGTH, max_length=FINGERPRINT_LENGTH)
    user_ids: tuple[str, ...] = Field(..., max_length=MAX_VAULT_USER_IDS)
    has_private_key: bool
    is_stub: bool = False
    created_at: datetime
    expires_at: datetime | None = None

    @field_validator("fingerprint")
    @classmethod
    def _normalise_fingerprint(cls, value: str) -> str:
        return normalise_fingerprint(value)

    @field_validator("user_ids")
    @classmethod
    def _validate_user_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for user_id in value:
            if len(user_id) > MAX_VAULT_USER_ID_LENGTH:
                raise ValueError("vault user ID is too long")
        return value

    @property
    def primary_user_id(self) -> str:
        return self.user_ids[0] if self.user_ids else self.fingerprint[-16:]

    def __repr__(self) -> str:
        return (
            f"VaultKeyEntry(fingerprint={self.fingerprint!r}, "
            f"has_private_key={self.has_private_key}, key_material=<segmented>)"
        )


class VaultManifest(BaseModel):
    """Encrypted payload of the vault. Never persisted in plaintext."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    created_by: str = Field(default="", max_length=MAX_VAULT_CREATED_BY_LENGTH)
    created_at: datetime
    app_version: str
    description: str = Field(default="", max_length=MAX_VAULT_DESCRIPTION_LENGTH)
    keys: tuple[VaultKeyEntry, ...] = Field(..., max_length=MAX_VAULT_KEYS)

    def __repr__(self) -> str:
        return (
            f"VaultManifest(created_at={self.created_at.isoformat()}, "
            f"key_count={len(self.keys)}, keys=<redacted>)"
        )
