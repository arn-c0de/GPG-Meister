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
from gpg_meister.storage.metadata_store import MetadataStore

MAX_PUBLIC_KEY_IMPORT_BYTES = 2 * 1024 * 1024
MAX_PUBLIC_KEY_IMPORT_COUNT = 32
PUBLIC_KEY_BLOCK = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
PRIVATE_KEY_BLOCK = "-----BEGIN PGP PRIVATE KEY BLOCK-----"


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
    def __init__(
        self,
        *,
        gpg: GPGService,
        audit: AuditLog,
        metadata: MetadataStore | None = None,
    ) -> None:
        self._gpg = gpg
        self._audit = audit
        self._metadata = metadata

    # ------------------------------------------------------------------ listing

    def list_keys(self) -> list[KeyInfo]:
        keys = self._gpg.list_keys(secret=False)
        if self._metadata is None:
            return keys

        metadata_rows = {
            str(row["fingerprint"]): row
            for row in self._metadata.list_keys()
        }
        return [self._merge_key_metadata(key, metadata_rows.get(key.fingerprint)) for key in keys]

    def find(self, fingerprint: str) -> KeyInfo:
        key = self._gpg.find_key(fingerprint)
        if self._metadata is None:
            return key
        return self._merge_key_metadata(key, self._metadata.get_key(key.fingerprint))

    def update_context(
        self,
        fingerprint: str,
        *,
        label: str | None = None,
        purpose: str | None = None,
        platform: str | None = None,
        notes: str | None = None,
    ) -> KeyInfo:
        fp = validate_fingerprint(fingerprint)
        # Ensure the key exists in the keyring before persisting user context.
        self._gpg.find_key(fp)
        if self._metadata is None:
            return self.find(fp)
        self._metadata.upsert_key(
            fp,
            label=label,
            purpose=purpose,
            platform=platform,
            notes=notes,
        )
        return self.find(fp)

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
        label: str | None = None,
        purpose: str | None = None,
        platform: str | None = None,
        notes: str | None = None,
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
        if self._metadata is not None and any(
            value is not None and value.strip()
            for value in (label, purpose, platform, notes)
        ):
            self._metadata.upsert_key(
                fp,
                label=label,
                purpose=purpose,
                platform=platform,
                notes=notes,
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
        armored = _validate_public_import_blob(armored)
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
        if len(entries) > MAX_PUBLIC_KEY_IMPORT_COUNT:
            raise ValueError("too many keys in one import batch")
        return tuple(entries)

    def import_armored(self, armored: str) -> list[str]:
        armored = _validate_public_import_blob(armored)
        try:
            fps = self._gpg.import_key(armored)
        except Exception as exc:
            self._audit.emit(
                "key_imported",
                outcome=OUTCOME_FAILED,
                reason=type(exc).__name__,
            )
            raise
        if len(fps) > MAX_PUBLIC_KEY_IMPORT_COUNT:
            raise ValueError("too many keys in one import batch")
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

    def _merge_key_metadata(
        self,
        key: KeyInfo,
        row: dict[str, str | None] | None,
    ) -> KeyInfo:
        if row is None:
            return key
        return key.model_copy(update={
            "label": row.get("label") or "",
            "purpose": row.get("purpose") or "",
            "platform": row.get("platform") or "",
            "notes": row.get("notes") or "",
        })


def _validate_public_import_blob(armored: str) -> str:
    blob = armored.strip()
    if not blob:
        raise ValueError("no key data entered")
    if len(blob.encode("utf-8")) > MAX_PUBLIC_KEY_IMPORT_BYTES:
        raise ValueError("public key import is too large")
    if "\x00" in blob:
        raise ValueError("binary key data is not accepted in the public-key dialog")
    if PRIVATE_KEY_BLOCK in blob:
        raise ValueError("private-key material cannot be imported in the public-key dialog")
    if PUBLIC_KEY_BLOCK not in blob:
        raise ValueError("expected an armored public key block")
    return blob
