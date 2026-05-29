"""Message-operation result models (encrypt / decrypt / sign / verify)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from gpg_meister.models.key_info import TrustLevel


class SignatureStatus(StrEnum):
    """Outcome of evaluating a GnuPG signature.

    Validity is derived from the ``[GNUPG:]`` status records, never from the
    process exit code: gpg exits 0 even when the signing key is revoked or
    expired (``REVKEYSIG`` / ``EXPKEYSIG``), so a returncode-based check would
    report such signatures as valid. Only :attr:`VALID` is a trustworthy
    signature; every other non-:attr:`NONE` value verified cryptographically
    but must not be trusted as-is.
    """

    NONE = "none"  # payload carried no signature
    VALID = "valid"  # GOODSIG + VALIDSIG, key neither revoked nor expired
    INVALID = "invalid"  # BADSIG — content does not match the signature
    REVOKED_KEY = "revoked_key"  # REVKEYSIG — good sig from a revoked key
    EXPIRED_KEY = "expired_key"  # EXPKEYSIG — good sig from an expired key
    EXPIRED_SIG = "expired_sig"  # EXPSIG — the signature itself has expired
    ERROR = "error"  # ERRSIG — could not verify (e.g. missing public key)

    @property
    def is_valid(self) -> bool:
        """True only for a fully trustworthy signature."""
        return self is SignatureStatus.VALID

    @property
    def is_present(self) -> bool:
        """True when the payload carried a signature at all."""
        return self is not SignatureStatus.NONE

    @property
    def summary(self) -> str:
        """Short human-readable label for UI display."""
        return {
            SignatureStatus.NONE: "no signature",
            SignatureStatus.VALID: "valid",
            SignatureStatus.INVALID: "INVALID",
            SignatureStatus.REVOKED_KEY: "INVALID — signing key REVOKED",
            SignatureStatus.EXPIRED_KEY: "INVALID — signing key EXPIRED",
            SignatureStatus.EXPIRED_SIG: "INVALID — signature EXPIRED",
            SignatureStatus.ERROR: "could not be verified",
        }[self]


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
    signature_status: SignatureStatus = SignatureStatus.NONE
    signer_trust: TrustLevel = TrustLevel.UNKNOWN
    decrypted_with_fingerprint: str | None = None

    @property
    def signature_valid(self) -> bool:
        """Backwards-compatible flag: true only for a fully trustworthy signature."""
        return self.signature_status.is_valid

    def __repr__(self) -> str:
        return (
            f"DecryptResult(signer_fingerprint={self.signer_fingerprint!r}, "
            f"signature_valid={self.signature_valid}, plaintext=<redacted "
            f"{len(self.plaintext)} bytes>)"
        )


class SignResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    armored_signature: str
    signing_fingerprint: str
    detached: bool = False
    created_at: datetime


class VerifyResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    signature_status: SignatureStatus = SignatureStatus.NONE
    signer_fingerprint: str | None = None
    signer_trust: TrustLevel = TrustLevel.UNKNOWN
    signed_at: datetime | None = None
    failure_reason: str | None = Field(default=None)

    @property
    def signature_valid(self) -> bool:
        """Backwards-compatible flag: true only for a fully trustworthy signature."""
        return self.signature_status.is_valid
