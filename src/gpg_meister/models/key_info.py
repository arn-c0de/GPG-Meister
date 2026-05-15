"""Domain model for a GPG key as exposed to the rest of the application."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

FINGERPRINT_LENGTH = 40
_FINGERPRINT_CHARS = set("0123456789ABCDEF")


class KeyAlgorithm(StrEnum):
    RSA = "RSA"
    DSA = "DSA"
    ECDSA = "ECDSA"
    EDDSA = "EDDSA"
    ECDH = "ECDH"
    UNKNOWN = "UNKNOWN"


class TrustLevel(StrEnum):
    UNKNOWN = "unknown"
    NEVER = "never"
    MARGINAL = "marginal"
    FULL = "full"
    ULTIMATE = "ultimate"


class KeyInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    fingerprint: str = Field(..., min_length=FINGERPRINT_LENGTH, max_length=FINGERPRINT_LENGTH)
    user_ids: tuple[str, ...]
    algorithm: KeyAlgorithm
    raw_algorithm_id: str = ""
    length: int = Field(..., gt=0)
    created_at: datetime
    expires_at: datetime | None = None
    is_revoked: bool = False
    has_private_key: bool = False
    is_stub: bool = False
    trust: TrustLevel = TrustLevel.UNKNOWN
    label: str = ""
    purpose: str = ""
    platform: str = ""
    notes: str = ""
    is_favorite: bool = False

    @field_validator("fingerprint")
    @classmethod
    def _validate_fingerprint(cls, value: str) -> str:
        upper = value.upper()
        if len(upper) != FINGERPRINT_LENGTH or not set(upper).issubset(_FINGERPRINT_CHARS):
            raise ValueError("fingerprint must be 40 uppercase hex characters")
        return upper

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(tz=self.expires_at.tzinfo) >= self.expires_at
