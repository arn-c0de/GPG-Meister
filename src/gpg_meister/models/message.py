"""Message-operation result models (encrypt / decrypt / sign / verify)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from gpg_meister.models.key_info import TrustLevel


class EncryptResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    armored_ciphertext: str
    recipient_fingerprints: tuple[str, ...]
    signing_fingerprint: str | None = None
    created_at: datetime


class DecryptResult(BaseModel):
    """Decrypt result. plaintext is sensitive — never logged."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    plaintext: bytes
    signer_fingerprint: str | None = None
    signature_valid: bool = False
    signer_trust: TrustLevel = TrustLevel.UNKNOWN
    decrypted_with_fingerprint: str | None = None

    def __repr__(self) -> str:
        return (
            f"DecryptResult(signer_fingerprint={self.signer_fingerprint!r}, "
            f"signature_valid={self.signature_valid}, plaintext=<redacted "
            f"{len(self.plaintext)} bytes>)"
        )

    def __str__(self) -> str:
        return self.__repr__()


class SignResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    armored_signature: str
    signing_fingerprint: str
    detached: bool = False
    created_at: datetime


class VerifyResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    signature_valid: bool
    signer_fingerprint: str | None = None
    signer_trust: TrustLevel = TrustLevel.UNKNOWN
    signed_at: datetime | None = None
    failure_reason: str | None = Field(default=None)
