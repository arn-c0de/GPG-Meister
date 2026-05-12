"""Vault orchestration (planv2.md §4.6).

Composes:
- `gpg_service` to export and import key material,
- `security.kdf` to derive a vault key from a passphrase,
- `security.aead` to encrypt/decrypt the manifest with AAD-bound header bytes,
- `security.vault_format` to pack/unpack the binary frame,
- `storage.atomic_write` for crash-safe writes,
- `storage.file_lock` to serialise concurrent vault writers,
- `storage.audit_log` to record every key-export and vault-creation event.

Nothing in this module ever writes plaintext key material to disk.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import msgpack

from gpg_meister import __version__ as APP_VERSION
from gpg_meister.models.kdf_params import KDFAlgorithm, KDFParams, high_memory_params
from gpg_meister.models.vault import (
    NONCE_LEN,
    CipherAlgorithm,
    CipherParams,
    KDFFields,
    VaultHeader,
    VaultKeyEntry,
    VaultManifest,
)
from gpg_meister.security.aead import decrypt as aead_decrypt
from gpg_meister.security.aead import encrypt as aead_encrypt
from gpg_meister.security.aead import generate_nonce
from gpg_meister.security.errors import DecryptionError, VaultFormatError
from gpg_meister.security.kdf import derive_key, generate_salt
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.security.vault_format import pack as vault_pack
from gpg_meister.security.vault_format import unpack as vault_unpack
from gpg_meister.services.errors import GPGKeyNotFoundError, ServiceError
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.services.validation import validate_fingerprint
from gpg_meister.storage.atomic_write import atomic_write_bytes
from gpg_meister.storage.audit_log import OUTCOME_FAILED, OUTCOME_OK, AuditLog
from gpg_meister.storage.file_lock import FileLock, FileLockTimeoutError


class VaultServiceError(ServiceError):
    """Vault operation failed at the service layer."""


@dataclass(frozen=True)
class VaultDescriptor:
    """High-level vault metadata returned to the UI."""

    path: Path
    sha256: str
    key_count: int


@dataclass(frozen=True)
class VaultPreview:
    """Read-only preview of a vault's contents (for the import wizard, §14.4)."""

    path: Path
    created_at: datetime
    app_version: str
    description: str
    keys: tuple[VaultKeyEntry, ...]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _build_header(
    *,
    cipher: CipherAlgorithm,
    salt: bytes,
    nonce: bytes,
    params: KDFParams,
) -> VaultHeader:
    return VaultHeader(
        kdf=KDFFields(
            algorithm=KDFAlgorithm.ARGON2ID,
            salt_b64=base64.b64encode(salt).decode("ascii"),
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
        ),
        cipher=CipherParams(
            algorithm=cipher,
            nonce_b64=base64.b64encode(nonce).decode("ascii"),
        ),
    )


def _serialise_manifest(manifest: VaultManifest) -> bytes:
    """Serialise the manifest to msgpack bytes.

    `msgpack.packb` is invoked with `use_bin_type=True` and `datetime=True` so
    datetimes round-trip without precision loss.
    """
    obj = manifest.model_dump(mode="json")
    return msgpack.packb(obj, use_bin_type=True)  # type: ignore[no-any-return]


def _deserialise_manifest(blob: bytes) -> VaultManifest:
    obj = msgpack.unpackb(blob, raw=False)
    if not isinstance(obj, dict):
        raise VaultFormatError("vault payload is not a manifest object")
    try:
        return VaultManifest.model_validate(obj)
    except Exception as exc:
        raise VaultFormatError(f"manifest validation failed: {exc}") from exc


class VaultService:
    """Stateless façade over the vault create / open flows."""

    def __init__(
        self,
        *,
        gpg: GPGService,
        audit: AuditLog,
    ) -> None:
        self._gpg = gpg
        self._audit = audit

    # ------------------------------------------------------------------- create

    def create(
        self,
        *,
        target_path: Path,
        master_passphrase: SecureBytes,
        gpg_passphrase: SecureBytes,
        fingerprints: Iterable[str],
        description: str = "",
        created_by: str = "",
        cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305,
        kdf_params: KDFParams | None = None,
    ) -> VaultDescriptor:
        """Build a vault from the supplied key fingerprints.

        Order of operations (planv2.md §4.6):
          1. Acquire an exclusive file lock on the target.
          2. Validate fingerprints.
          3. Export private keys via the GPG service (using `gpg_passphrase`).
          4. Build the manifest and msgpack-serialise.
          5. Generate salt+nonce, derive vault key.
          6. Encrypt with AAD = canonical header bytes.
          7. Atomically write the binary frame.
          8. Write SHA-256 sidecar atomically.
          9. Emit `vault_created` audit event.
        """
        fps = tuple(validate_fingerprint(fp) for fp in fingerprints)
        if not fps:
            raise VaultServiceError("at least one key fingerprint is required")

        params = kdf_params or high_memory_params()
        target_path = Path(target_path).resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            lock = FileLock(target_path, exclusive=True, timeout=5.0)
            lock.acquire()
        except FileLockTimeoutError as exc:
            raise VaultServiceError(
                f"another process is writing to {target_path}"
            ) from exc

        try:
            entries = self._collect_entries(fps, gpg_passphrase)

            manifest = VaultManifest(
                created_by=created_by,
                created_at=_utc_now(),
                app_version=APP_VERSION,
                description=description,
                keys=entries,
            )
            manifest_bytes = _serialise_manifest(manifest)

            salt = generate_salt(params.salt_len)
            nonce = generate_nonce()
            header = _build_header(cipher=cipher, salt=salt, nonce=nonce, params=params)

            with derive_key(master_passphrase, salt, params) as vault_key:
                frame, header_bytes = vault_pack(header, b"")
                ciphertext = aead_encrypt(
                    plaintext=manifest_bytes,
                    key=vault_key,
                    nonce=nonce,
                    associated_data=header_bytes,
                    cipher=cipher,
                )
                # Repack with the real ciphertext now that we have it. The header
                # bytes are deterministic, so the second pack yields the same
                # AAD bytes used during encryption.
                frame, _ = vault_pack(header, ciphertext)

            atomic_write_bytes(target_path, frame, mode=0o600)
            sha = hashlib.sha256(frame).hexdigest()
            atomic_write_bytes(
                target_path.with_name(target_path.name + ".sha256"),
                f"{sha}  {target_path.name}\n".encode(),
                mode=0o600,
            )

            self._audit.emit(
                "vault_created",
                outcome=OUTCOME_OK,
                path=str(target_path),
                key_count=len(entries),
                cipher=cipher.value,
                sha256=sha,
            )
            return VaultDescriptor(path=target_path, sha256=sha, key_count=len(entries))
        except Exception as exc:
            self._audit.emit(
                "vault_created",
                outcome=OUTCOME_FAILED,
                path=str(target_path),
                reason=type(exc).__name__,
            )
            raise
        finally:
            lock.release()

    def _collect_entries(
        self, fingerprints: tuple[str, ...], gpg_passphrase: SecureBytes
    ) -> tuple[VaultKeyEntry, ...]:
        entries: list[VaultKeyEntry] = []
        for fp in fingerprints:
            try:
                key = self._gpg.find_key(fp)
            except GPGKeyNotFoundError as exc:
                raise VaultServiceError(f"key {fp} not in keyring") from exc

            public_armored = self._gpg.export_public_key(fp)
            if key.has_private_key:
                private_armored = self._gpg.export_private_key(fp, gpg_passphrase)
                self._audit.emit(
                    "key_exported_private",
                    outcome=OUTCOME_OK,
                    fingerprint=fp,
                )
            else:
                private_armored = None
                self._audit.emit(
                    "key_exported_public",
                    outcome=OUTCOME_OK,
                    fingerprint=fp,
                )

            entries.append(
                VaultKeyEntry(
                    fingerprint=fp,
                    user_ids=key.user_ids,
                    public_key_armored=public_armored,
                    private_key_armored=private_armored,
                    has_private_key=key.has_private_key,
                    created_at=key.created_at,
                    expires_at=key.expires_at,
                )
            )
        return tuple(entries)

    # --------------------------------------------------------------------- open

    def preview(self, *, source_path: Path, master_passphrase: SecureBytes) -> VaultPreview:
        """Decrypt the manifest and return a read-only preview.

        The local keyring is *not* modified — use `import_keys` to commit a
        subset of the preview into the keyring.
        """
        manifest, _ = self._open(source_path=source_path, master_passphrase=master_passphrase)
        return VaultPreview(
            path=Path(source_path).resolve(),
            created_at=manifest.created_at,
            app_version=manifest.app_version,
            description=manifest.description,
            keys=manifest.keys,
        )

    def import_keys(
        self,
        *,
        source_path: Path,
        master_passphrase: SecureBytes,
        fingerprints: Iterable[str] | None = None,
    ) -> list[str]:
        """Decrypt and import (a subset of) the vault's keys into the local keyring.

        If `fingerprints` is None, every key in the manifest is imported.
        Returns the list of fingerprints that were imported successfully.
        """
        manifest, src_path = self._open(
            source_path=source_path, master_passphrase=master_passphrase
        )
        wanted = (
            {validate_fingerprint(fp) for fp in fingerprints}
            if fingerprints is not None
            else {entry.fingerprint for entry in manifest.keys}
        )

        imported: list[str] = []
        for entry in manifest.keys:
            if entry.fingerprint not in wanted:
                continue
            armored = entry.private_key_armored or entry.public_key_armored
            try:
                results = self._gpg.import_key(armored)
            except Exception as exc:
                self._audit.emit(
                    "key_imported",
                    outcome=OUTCOME_FAILED,
                    fingerprint=entry.fingerprint,
                    reason=type(exc).__name__,
                )
                raise
            self._audit.emit(
                "key_imported",
                outcome=OUTCOME_OK,
                fingerprint=entry.fingerprint,
                has_private_key=entry.has_private_key,
            )
            imported.extend(results)

        self._audit.emit(
            "vault_imported",
            outcome=OUTCOME_OK,
            path=str(src_path),
            key_count=len(imported),
        )
        return imported

    # ----------------------------------------------------------------- internal

    def _open(
        self, *, source_path: Path, master_passphrase: SecureBytes
    ) -> tuple[VaultManifest, Path]:
        src = Path(source_path).resolve()
        if not src.exists():
            raise VaultServiceError(f"vault file does not exist: {src}")

        with FileLock(src, exclusive=False, timeout=5.0):
            data = src.read_bytes()

        try:
            frame = vault_unpack(data)
        except VaultFormatError:
            self._audit.emit(
                "vault_import_failed",
                outcome=OUTCOME_FAILED,
                path=str(src),
                reason="format",
            )
            raise

        kdf_params = frame.header.kdf.to_params()
        salt = frame.header.kdf.salt
        nonce = frame.header.cipher.nonce
        cipher = frame.header.cipher.algorithm

        with derive_key(master_passphrase, salt, kdf_params) as vault_key:
            try:
                plaintext = aead_decrypt(
                    ciphertext=frame.ciphertext,
                    key=vault_key,
                    nonce=nonce,
                    associated_data=frame.header_bytes,
                    cipher=cipher,
                )
            except DecryptionError:
                self._audit.emit(
                    "vault_import_failed",
                    outcome=OUTCOME_FAILED,
                    path=str(src),
                    reason="decryption",
                )
                raise

        # Verify the sidecar (best-effort — missing sidecar is fine, mismatch warns).
        sidecar = src.with_name(src.name + ".sha256")
        if sidecar.exists():
            expected = sidecar.read_text(encoding="utf-8").split()[0].strip().lower()
            actual = hashlib.sha256(data).hexdigest().lower()
            if expected != actual:
                self._audit.emit(
                    "vault_import_failed",
                    outcome=OUTCOME_FAILED,
                    path=str(src),
                    reason="checksum",
                )
                raise VaultServiceError(
                    f"vault checksum mismatch: expected {expected[:16]}…"
                )

        manifest = _deserialise_manifest(plaintext)
        # NONCE_LEN sanity check defends against header tampering that survives the
        # AEAD (it should never happen — AAD covers everything — but it's cheap).
        if len(nonce) != NONCE_LEN:
            raise VaultFormatError("vault nonce length mismatch")
        return manifest, src
