"""Message encryption / decryption / signing service.

Mirrors `gpg_service` semantics but adds audit-log hooks and recipient analysis
for the UI (planv2.md §14.2). The encrypt method consumes a tuple of fingerprints
together with their pre-computed user IDs, so the UI can build the recipient
confirmation panel without consulting GPG mid-flow.
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from datetime import UTC, datetime

from gpg_meister.models.key_info import KeyAlgorithm, TrustLevel
from gpg_meister.models.message import (
    DecryptResult,
    EncryptResult,
    SignResult,
    VerifyResult,
)
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
        always_trust: bool = False,
        trust_confirmed: bool = False,
    ) -> EncryptResult:
        recipients = tuple(validate_fingerprint(fp) for fp in recipient_fingerprints)
        signer = validate_fingerprint(sign_with) if sign_with else None
        self._enforce_recipient_policy(recipients, trust_confirmed=trust_confirmed)
        if always_trust and not trust_confirmed:
            raise ValueError("recipient trust must be confirmed before encryption")

        try:
            armored = self._gpg.encrypt(
                plaintext,
                recipient_fingerprints=recipients,
                sign_with=signer,
                passphrase=passphrase,
                always_trust=always_trust,
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

    def _enforce_recipient_policy(
        self,
        recipients: Sequence[str],
        *,
        trust_confirmed: bool,
    ) -> None:
        if not recipients:
            raise ValueError("at least one recipient is required")
        for fp in recipients:
            key = self._gpg.find_key(fp)
            if key.is_revoked:
                raise ValueError("cannot encrypt to a revoked recipient key")
            if key.is_expired:
                raise ValueError("cannot encrypt to an expired recipient key")
            if key.algorithm in (KeyAlgorithm.DSA, KeyAlgorithm.UNKNOWN):
                raise ValueError("cannot encrypt to an unsupported recipient key algorithm")
            if key.algorithm is KeyAlgorithm.RSA and key.length < 2048:
                raise ValueError("cannot encrypt to an RSA key below 2048 bits")
            if key.trust in (TrustLevel.UNKNOWN, TrustLevel.NEVER) and not trust_confirmed:
                raise ValueError("recipient trust must be confirmed before encryption")

    # ----------------------------------------------------------------- decrypt

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        passphrase: SecureBytes | None = None,
    ) -> DecryptResult:
        try:
            plaintext, signer, signature_status, decrypted_with = self._gpg.decrypt(
                ciphertext, passphrase=passphrase
            )
        except Exception as exc:
            self._audit.emit(
                "message_decrypt_failed",
                outcome=OUTCOME_FAILED,
                reason=type(exc).__name__,
            )
            raise

        signer_trust = TrustLevel.UNKNOWN
        if signer:
            with contextlib.suppress(Exception):
                signer_trust = self._gpg.find_key(signer).trust

        self._audit.emit(
            "message_decrypted",
            outcome=OUTCOME_OK,
            byte_count=len(plaintext),
            signer=signer or "",
            signature_status=signature_status.value,
            signer_trust=signer_trust.value if signer else "",
            decrypted_with=decrypted_with or "",
        )
        return DecryptResult(
            plaintext=plaintext,
            signer_fingerprint=signer,
            signature_status=signature_status,
            signer_trust=signer_trust,
            decrypted_with_fingerprint=decrypted_with,
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
        _validate_text_payload(data)
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
        _validate_text_payload(data)
        signature_status, signer, signed_at = self._gpg.verify(
            data, detached_signature=detached_signature
        )
        signer_trust = TrustLevel.UNKNOWN
        if signer:
            with contextlib.suppress(Exception):
                signer_trust = self._gpg.find_key(signer).trust
        return VerifyResult(
            signature_status=signature_status,
            signer_fingerprint=signer,
            signer_trust=signer_trust,
            signed_at=signed_at,
            failure_reason=(
                None if signature_status.is_valid else signature_status.summary
            ),
        )


def _validate_text_payload(data: bytes) -> None:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("message signing and verification are text-only") from exc
    if b"\x00" in data:
        raise ValueError("message signing and verification are text-only")
