"""Key lifecycle service.

Sits between the UI layer and `gpg_service`, adding:
- Audit-log hooks for every state-changing operation.
- Input validation that mirrors the security expectations of the UI.
- Conflict detection for imports (does the local keyring already have this key?).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.errors import GPGKeyNotFoundError
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.services.validation import validate_fingerprint
from gpg_meister.storage.audit_log import OUTCOME_FAILED, OUTCOME_OK, AuditLog


class ImportConflict(StrEnum):
    NEW = "new"
    ALREADY_PRESENT = "already_present"
    ALREADY_HAS_PRIVATE = "already_has_private"


@dataclass(frozen=True)
class ImportPlanEntry:
    fingerprint: str
    user_ids: tuple[str, ...]
    has_private_key: bool
    conflict: ImportConflict


class KeyService:
    def __init__(self, *, gpg: GPGService, audit: AuditLog) -> None:
        self._gpg = gpg
        self._audit = audit

    # ------------------------------------------------------------------ listing

    def list_keys(self) -> list[KeyInfo]:
        return self._gpg.list_keys(secret=False)

    def find(self, fingerprint: str) -> KeyInfo:
        return self._gpg.find_key(fingerprint)

    # ----------------------------------------------------------------- mutation

    def create(
        self,
        *,
        name: str,
        email: str,
        algorithm: KeyAlgorithm,
        length: int,
        expiry: str,
        passphrase: SecureBytes,
    ) -> KeyInfo:
        try:
            fp = self._gpg.generate_key(
                name=name,
                email=email,
                algorithm=algorithm,
                length=length,
                expiry=expiry,
                passphrase=passphrase,
            )
        except Exception as exc:
            self._audit.emit(
                "key_generated",
                outcome=OUTCOME_FAILED,
                algorithm=algorithm.value,
                reason=type(exc).__name__,
            )
            raise
        self._audit.emit(
            "key_generated",
            outcome=OUTCOME_OK,
            fingerprint=fp,
            algorithm=algorithm.value,
            length=length,
        )
        return self.find(fp)

    def delete(
        self,
        fingerprint: str,
        *,
        including_secret: bool,
        passphrase: SecureBytes | None = None,
    ) -> None:
        fp = validate_fingerprint(fingerprint)
        try:
            self._gpg.delete_key(
                fp,
                including_secret=including_secret,
                passphrase=passphrase,
            )
        except Exception as exc:
            self._audit.emit(
                "key_deleted",
                outcome=OUTCOME_FAILED,
                fingerprint=fp,
                reason=type(exc).__name__,
            )
            raise
        self._audit.emit(
            "key_deleted",
            outcome=OUTCOME_OK,
            fingerprint=fp,
            including_secret=including_secret,
        )

    # -------------------------------------------------------------------- import

    def plan_import(self, armored: str) -> tuple[ImportPlanEntry, ...]:
        """Dry-run analysis of an armored block: which keys does it carry and how
        does each compare to the existing keyring?

        python-gnupg does not expose a direct dry-run, so the production path is
        to extract fingerprints by parsing via `gpg --show-keys` if needed. As a
        first iteration we delegate to a real import and inspect the result, then
        leave the keyring untouched if conflicts dominate — the safer alternative
        is to require the caller to pass a single armored key per call. This
        method is conservative: it inspects fingerprints already in the keyring
        and computes the conflict label without touching anything.
        """
        # The simplest, side-effect-free approach is to ask GPG to list keys from
        # a temporary, in-memory perspective. python-gnupg's `scan_keys` does
        # exactly that.
        rows = self._gpg._gpg.scan_keys_mem(armored)
        existing_pub = {k.fingerprint for k in self.list_keys()}
        existing_secret = {
            k.fingerprint
            for k in self._gpg.list_keys(secret=True)
        }

        entries: list[ImportPlanEntry] = []
        for row in rows:
            fp = str(row.get("fingerprint", "")).upper()
            if not fp:
                continue
            uids = tuple(row.get("uids", []))
            has_priv = "sec" in str(row.get("type", ""))
            if fp in existing_secret:
                conflict = ImportConflict.ALREADY_HAS_PRIVATE
            elif fp in existing_pub:
                conflict = ImportConflict.ALREADY_PRESENT
            else:
                conflict = ImportConflict.NEW
            entries.append(
                ImportPlanEntry(
                    fingerprint=fp,
                    user_ids=uids,
                    has_private_key=has_priv,
                    conflict=conflict,
                )
            )
        return tuple(entries)

    def import_armored(self, armored: str) -> list[str]:
        try:
            fps = self._gpg.import_key(armored)
        except Exception as exc:
            self._audit.emit(
                "key_imported",
                outcome=OUTCOME_FAILED,
                reason=type(exc).__name__,
            )
            raise
        for fp in fps:
            self._audit.emit("key_imported", outcome=OUTCOME_OK, fingerprint=fp)
        return fps

    # ------------------------------------------------------------------- export

    def export_public(self, fingerprint: str) -> str:
        fp = validate_fingerprint(fingerprint)
        armored = self._gpg.export_public_key(fp)
        self._audit.emit("key_exported_public", outcome=OUTCOME_OK, fingerprint=fp)
        return armored

    def export_private(self, fingerprint: str, passphrase: SecureBytes) -> str:
        fp = validate_fingerprint(fingerprint)
        try:
            armored = self._gpg.export_private_key(fp, passphrase)
        except Exception as exc:
            self._audit.emit(
                "key_exported_private",
                outcome=OUTCOME_FAILED,
                fingerprint=fp,
                reason=type(exc).__name__,
            )
            raise
        self._audit.emit(
            "key_exported_private",
            outcome=OUTCOME_OK,
            fingerprint=fp,
        )
        return armored

    # ---------------------------------------------------------------- helpers

    def collect_user_ids(self, fingerprints: Iterable[str]) -> dict[str, tuple[str, ...]]:
        """Map each fingerprint to its user IDs. Useful for the recipient panel
        (planv2.md §14.2). Raises if any fingerprint is unknown."""
        result: dict[str, tuple[str, ...]] = {}
        for fp in fingerprints:
            try:
                info = self.find(fp)
            except GPGKeyNotFoundError as exc:
                raise GPGKeyNotFoundError(str(exc)) from exc
            result[info.fingerprint] = info.user_ids
        return result
