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
    MAX_HASH_LEN,
    MAX_MEMORY_COST_KB,
    MAX_PARALLELISM,
    MAX_SALT_LEN,
    MAX_TIME_COST,
    MIN_HASH_LEN,
    MIN_MEMORY_COST_KB,
    MIN_SALT_LEN,
    MIN_TIME_COST,
    KDFAlgorithm,
    KDFParams,
)
from gpg_meister.models.key_info import _FINGERPRINT_CHARS, FINGERPRINT_LENGTH

VAULT_FORMAT_TAG = "GPGMEISTER_VAULT"
VAULT_FORMAT_VERSION = 2
NONCE_LEN = 12
MAX_VAULT_KEYS = 1024
MAX_VAULT_USER_IDS = 16
MAX_VAULT_USER_ID_LENGTH = 512
MAX_VAULT_DESCRIPTION_LENGTH = 4096
MAX_VAULT_CREATED_BY_LENGTH = 256
MAX_VAULT_ARMOR_LENGTH = 2 * 1024 * 1024


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
    time_cost: int = Field(..., ge=MIN_TIME_COST, le=MAX_TIME_COST)
    memory_cost: int = Field(..., ge=MIN_MEMORY_COST_KB, le=MAX_MEMORY_COST_KB)
    parallelism: int = Field(..., ge=1, le=MAX_PARALLELISM)
    hash_len: int = Field(..., ge=MIN_HASH_LEN, le=MAX_HASH_LEN)

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


class VaultHeader(BaseModel):
    """The unencrypted vault header. Bytes form is AAD-bound to the AEAD tag."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    format: str = Field(default=VAULT_FORMAT_TAG)
    version: int = Field(default=VAULT_FORMAT_VERSION)
    kdf: KDFFields
    cipher: CipherParams

    @field_validator("format")
    @classmethod
    def _validate_format(cls, value: str) -> str:
        if value != VAULT_FORMAT_TAG:
            raise ValueError(f"unknown vault format tag: {value!r}")
        return value

    @field_validator("version")
    @classmethod
    def _validate_version(cls, value: int) -> int:
        if value != VAULT_FORMAT_VERSION:
            raise ValueError(f"unsupported vault version: {value}")
        return value


class VaultKeyEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    fingerprint: str = Field(..., min_length=FINGERPRINT_LENGTH, max_length=FINGERPRINT_LENGTH)
    user_ids: tuple[str, ...] = Field(..., max_length=MAX_VAULT_USER_IDS)
    public_key_armored: str = Field(..., min_length=1, max_length=MAX_VAULT_ARMOR_LENGTH)
    private_key_armored: str | None = Field(default=None, max_length=MAX_VAULT_ARMOR_LENGTH)
    has_private_key: bool
    created_at: datetime
    expires_at: datetime | None = None

    @field_validator("fingerprint")
    @classmethod
    def _normalise_fingerprint(cls, value: str) -> str:
        upper = value.upper()
        if len(upper) != FINGERPRINT_LENGTH or not set(upper).issubset(_FINGERPRINT_CHARS):
            raise ValueError("fingerprint must be 40 uppercase hex characters")
        return upper

    @field_validator("user_ids")
    @classmethod
    def _validate_user_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for user_id in value:
            if len(user_id) > MAX_VAULT_USER_ID_LENGTH:
                raise ValueError("vault user ID is too long")
        return value

    @model_validator(mode="after")
    def _validate_private_key_material(self) -> VaultKeyEntry:
        if self.has_private_key and not self.private_key_armored:
            raise ValueError("private key entry is missing private key material")
        return self

    def __repr__(self) -> str:
        return (
            f"VaultKeyEntry(fingerprint={self.fingerprint!r}, "
            f"has_private_key={self.has_private_key}, private_key_armored=<redacted>)"
        )

    def __str__(self) -> str:
        return self.__repr__()


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
