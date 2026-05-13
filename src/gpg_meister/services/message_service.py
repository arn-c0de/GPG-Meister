"""Message encryption / decryption / signing service.

Mirrors `gpg_service` semantics but adds audit-log hooks and recipient analysis
for the UI (planv2.md §14.2). The encrypt method consumes a tuple of fingerprints
together with their pre-computed user IDs, so the UI can build the recipient
confirmation panel without consulting GPG mid-flow.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from gpg_meister.models.message import DecryptResult, EncryptResult, SignResult, VerifyResult
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.services.validation import validate_fingerprint
from gpg_meister.storage.audit_log import OUTCOME_FAILED, OUTCOME_OK, AuditLog


class MessageService:
    def __init__(self, *, gpg: GPGService, audit: AuditLog) -> None:
        self._gpg = gpg
        self._audit = audit

    # ----------------------------------------------------------------- encrypt

    def encrypt(
        self,
        plaintext: bytes,
        *,
        recipient_fingerprints: Sequence[str],
        sign_with: str | None = None,
        passphrase: SecureBytes | None = None,
    ) -> EncryptResult:
        recipients = tuple(validate_fingerprint(fp) for fp in recipient_fingerprints)
        signer = validate_fingerprint(sign_with) if sign_with else None

        try:
            armored = self._gpg.encrypt(
                plaintext,
                recipient_fingerprints=recipients,
                sign_with=signer,
                passphrase=passphrase,
            )
        except Exception as exc:
            if signer:
                self._audit.emit(
                    "message_signed",
                    outcome=OUTCOME_FAILED,
                    fingerprint=signer,
                    reason=type(exc).__name__,
                )
            raise

        if signer:
            self._audit.emit(
                "message_signed",
                outcome=OUTCOME_OK,
                fingerprint=signer,
                recipient_count=len(recipients),
            )

        return EncryptResult(
            armored_ciphertext=armored,
            recipient_fingerprints=recipients,
            signing_fingerprint=signer,
            created_at=datetime.now(UTC),
        )

    # ----------------------------------------------------------------- decrypt

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        passphrase: SecureBytes,
    ) -> DecryptResult:
        try:
            plaintext, signer, valid = self._gpg.decrypt(ciphertext, passphrase=passphrase)
        except Exception as exc:
            self._audit.emit(
                "message_decrypt_failed",
                outcome=OUTCOME_FAILED,
                reason=type(exc).__name__,
            )
            raise

        self._audit.emit(
            "message_decrypted",
            outcome=OUTCOME_OK,
            byte_count=len(plaintext),
            signer=signer or "",
            signature_valid=valid,
        )
        return DecryptResult(
            plaintext=plaintext,
            signer_fingerprint=signer,
            signature_valid=valid,
        )

    # -------------------------------------------------------------------- sign

    def sign(
        self,
        data: bytes,
        *,
        fingerprint: str,
        passphrase: SecureBytes,
        detached: bool = True,
    ) -> SignResult:
        try:
            armored = self._gpg.sign(
                data,
                fingerprint=fingerprint,
                passphrase=passphrase,
                detached=detached,
            )
        except Exception as exc:
            self._audit.emit(
                "message_signed",
                outcome=OUTCOME_FAILED,
                fingerprint=fingerprint,
                reason=type(exc).__name__,
            )
            raise
        self._audit.emit(
            "message_signed",
            outcome=OUTCOME_OK,
            fingerprint=fingerprint,
            detached=detached,
        )
        return SignResult(
            armored_signature=armored,
            signing_fingerprint=fingerprint,
            detached=detached,
            created_at=datetime.now(UTC),
        )

    # ------------------------------------------------------------------ verify

    def verify(
        self,
        data: bytes,
        *,
        detached_signature: bytes | None = None,
    ) -> VerifyResult:
        valid, signer, signed_at = self._gpg.verify(
            data, detached_signature=detached_signature
        )
        return VerifyResult(
            signature_valid=valid,
            signer_fingerprint=signer,
            signed_at=signed_at,
        )
