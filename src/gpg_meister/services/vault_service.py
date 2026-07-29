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
import hmac
import io
import struct
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import msgpack

from gpg_meister import __version__ as APP_VERSION
from gpg_meister.models.kdf_params import (
    MAX_IMPORT_MEMORY_COST_KB,
    MAX_IMPORT_PARALLELISM,
    MAX_IMPORT_TIME_COST,
    MIN_MEMORY_COST_KB,
    MIN_TIME_COST,
    KDFAlgorithm,
    KDFParams,
    high_memory_params,
)
from gpg_meister.models.key_info import KeyInfo
from gpg_meister.models.vault import (
    MAX_VAULT_ARMOR_LENGTH,
    MAX_VAULT_KEY_SLOTS,
    MAX_VAULT_SLOT_LABEL_LENGTH,
    NONCE_LEN,
    VAULT_FORMAT_VERSION_SLOTS,
    CipherAlgorithm,
    CipherParams,
    KDFFields,
    VaultHeader,
    VaultKeyEntry,
    VaultKeySlot,
    VaultManifest,
    VaultSlotType,
)
from gpg_meister.security.aead import decrypt as aead_decrypt
from gpg_meister.security.aead import encrypt as aead_encrypt
from gpg_meister.security.aead import generate_nonce
from gpg_meister.security.errors import DecryptionError, VaultFormatError
from gpg_meister.security.kdf import derive_key, generate_salt
from gpg_meister.security.secure_bytes import (
    SecureBytes,
    _zero_bytes_object,
    zero_mutable_buffer,
)
from gpg_meister.security.vault_format import (
    HEADER_OFFSET,
    LENGTH_FIELD,
    MAX_CIPHERTEXT_SIZE,
    MAX_HEADER_SIZE,
    UnpackedFrame,
)
from gpg_meister.security.vault_format import pack as vault_pack
from gpg_meister.security.vault_format import unpack as vault_unpack
from gpg_meister.security.vault_keyslots import (
    file_key_from_bytes,
    generate_file_key,
    openpgp_slot,
    unwrap_with_passphrase,
    wrap_with_passphrase,
)
from gpg_meister.services.errors import (
    GPGCardError,
    GPGKeyNotFoundError,
    GPGPassphraseError,
    GPGProcessError,
    ServiceError,
)
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.services.key_service import remove_smuggled_key
from gpg_meister.services.validation import validate_fingerprint
from gpg_meister.storage.atomic_write import atomic_write_bytes
from gpg_meister.storage.audit_log import (
    OUTCOME_FAILED,
    OUTCOME_OK,
    AuditLog,
)
from gpg_meister.storage.file_lock import FileLock, FileLockTimeoutError
from gpg_meister.storage.metadata_store import MetadataStore
from gpg_meister.storage.permissions import ensure_dir, reject_symlink


class VaultServiceError(ServiceError):
    """Vault operation failed at the service layer."""


class VaultChecksumMismatchError(VaultServiceError):
    """Sidecar SHA-256 does not match the vault file.

    The vault's AEAD decryption already succeeded, so the ciphertext is
    intact. Only the external sidecar is out of sync (e.g. corrupted during
    transfer). Callers may offer the user an "open anyway" path.
    """


MAX_VAULT_FRAME_SIZE = HEADER_OFFSET + MAX_HEADER_SIZE + LENGTH_FIELD + MAX_CIPHERTEXT_SIZE
_U32 = struct.Struct(">I")
_FINGERPRINT_BYTES = 20


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


@dataclass(frozen=True)
class VaultUnlockSlot:
    """One advertised unlock method of a vault file."""

    fingerprint: str
    label: str


@dataclass(frozen=True)
class VaultUnlockInfo:
    """Which credentials open a vault — readable without decrypting anything."""

    version: int
    accepts_passphrase: bool
    smartcard_slots: tuple[VaultUnlockSlot, ...] = ()

    @property
    def accepts_smartcard(self) -> bool:
        return bool(self.smartcard_slots)


@dataclass(frozen=True)
class _CollectedEntry:
    entry: VaultKeyEntry
    public_key: bytes
    private_key: bytes | None


@dataclass(frozen=True)
class _KeySlice:
    public_start: int
    public_end: int
    private_start: int
    private_end: int


@dataclass
class _OpenedVault:
    manifest: VaultManifest
    src_path: Path
    plaintext: bytearray
    key_slices: dict[str, _KeySlice]

    def key_material(self, fingerprint: str) -> memoryview:
        key_slice = self.key_slices[fingerprint]
        start, end = (
            (key_slice.private_start, key_slice.private_end)
            if key_slice.private_end > key_slice.private_start
            else (key_slice.public_start, key_slice.public_end)
        )
        return memoryview(self.plaintext)[start:end]

    def close(self) -> None:
        if self.plaintext:
            view = memoryview(self.plaintext)
            try:
                zero_mutable_buffer(view)
            finally:
                view.release()


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

    `model_dump(mode="json")` converts datetimes to ISO-8601 strings first, so
    they round-trip without precision loss and without msgpack extension types.
    """
    obj = manifest.model_dump(mode="json")
    return msgpack.packb(obj, use_bin_type=True)  # type: ignore[no-any-return]


def _deserialise_manifest(blob: bytes | memoryview) -> VaultManifest:
    obj = msgpack.unpackb(
        blob,
        raw=False,
        max_str_len=64 * 1024,
        max_bin_len=64 * 1024,
        max_array_len=65536,
        max_map_len=65536,
    )
    if not isinstance(obj, dict):
        raise VaultFormatError("vault payload is not a manifest object")
    try:
        return VaultManifest.model_validate(obj)
    except Exception as exc:
        raise VaultFormatError(f"manifest validation failed: {exc}") from exc


def _append_key_material(
    payload: bytearray,
    *,
    fingerprint: str,
    public_key: bytes,
    private_key: bytes | None,
) -> None:
    if not public_key or len(public_key) > MAX_VAULT_ARMOR_LENGTH:
        raise VaultFormatError("public key material length is invalid")
    if private_key is not None and len(private_key) > MAX_VAULT_ARMOR_LENGTH:
        raise VaultFormatError("private key material length is invalid")
    payload.extend(bytes.fromhex(fingerprint))
    payload.extend(_U32.pack(len(public_key)))
    payload.extend(public_key)
    payload.extend(_U32.pack(len(private_key or b"")))
    if private_key:
        payload.extend(private_key)


def _serialise_segmented_payload(
    collected: tuple[_CollectedEntry, ...],
    manifest: VaultManifest,
) -> bytearray:
    manifest_bytes = _serialise_manifest(manifest)
    try:
        payload = bytearray(_U32.pack(len(manifest_bytes)))
        payload.extend(manifest_bytes)
    finally:
        _zero_bytes_object(manifest_bytes)
    for item in collected:
        _append_key_material(
            payload,
            fingerprint=item.entry.fingerprint,
            public_key=item.public_key,
            private_key=item.private_key,
        )
    return payload


def _read_u32(view: memoryview, offset: int) -> tuple[int, int]:
    if offset + _U32.size > len(view):
        raise VaultFormatError("vault payload is truncated")
    return _U32.unpack_from(view, offset)[0], offset + _U32.size


def _legacy_bytes_to_str(value: object) -> object:
    """Recursively decode msgpack ``bytes`` → ``str`` for legacy metadata.

    Key-material armor is popped out of the raw map as zeroable ``bytes`` *before*
    this runs, so this only ever touches the small, non-secret metadata fields —
    private key material must never reach this function and become an unzeroable
    immutable ``str``.
    """
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, dict):
        return {_legacy_bytes_to_str(k): _legacy_bytes_to_str(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_legacy_bytes_to_str(v) for v in value]
    return value


def _rebuild_legacy_segmented_payload(payload: bytearray) -> tuple[VaultManifest, int]:
    """Parse a legacy (pre-segmented, msgpack-map) vault and normalise it.

    Older vaults stored key armor inline in the msgpack manifest rather than in a
    length-prefixed segment stream. This rebuilds ``payload`` in place into the
    modern segmented form and returns ``(manifest, key_stream_offset)`` so the
    shared slice walk in the caller works unchanged. The plaintext has already
    been authenticated via AEAD, but we still defend against a peer-crafted vault
    an unsuspecting user imports. Key material is handled as zeroable ``bytes``
    throughout and the immutable intermediates are wiped on the way out.
    """
    collected_material: list[tuple[str, bytes, bytes | None]] = []
    try:
        stream = io.BytesIO(payload)
        # raw=True keeps every value as `bytes`. We pull the private/public
        # key armor straight out of the raw map below — *before* decoding any
        # metadata to `str` — so key material never becomes an unzeroable
        # immutable `str`. Only the small, non-secret metadata fields are
        # decoded to `str` for pydantic.
        manifest_obj = msgpack.unpack(
            stream,
            raw=True,
            max_str_len=MAX_VAULT_ARMOR_LENGTH,
            max_bin_len=MAX_VAULT_ARMOR_LENGTH,
            max_array_len=65536,
            max_map_len=65536,
            strict_map_key=False,
        )
        if not isinstance(manifest_obj, dict):
            raise VaultFormatError("legacy manifest is not a msgpack map")

        _pop_legacy_key_material(manifest_obj, collected_material)

        # Now decode the remaining (armor-free) metadata to str for pydantic.
        decoded_obj = _legacy_bytes_to_str(manifest_obj)
        if not isinstance(decoded_obj, dict):
            raise VaultFormatError("legacy manifest decoded to non-dict")

        manifest = VaultManifest.model_validate(decoded_obj)

        if collected_material:
            return manifest, _replace_with_segmented_payload(
                payload, manifest, collected_material
            )
        # Segmented-but-no-prefix (if it ever existed).
        return manifest, stream.tell()
    except VaultFormatError:
        raise
    except Exception as exc:
        raise VaultFormatError(f"legacy manifest decoding failed: {exc}") from exc
    finally:
        # Best-effort wipe of the immutable key-material intermediates; the
        # authoritative copy now lives in the (zeroable) payload bytearray.
        for _fp, _pub, _priv in collected_material:
            _zero_bytes_object(_pub)
            if _priv is not None:
                _zero_bytes_object(_priv)
        collected_material.clear()


def _pop_legacy_key_material(
    manifest_obj: dict[object, object],
    out: list[tuple[str, bytes, bytes | None]],
) -> None:
    """Pop key armor (as zeroable ``bytes``) out of the raw map before validation.

    Appends into ``out`` so the caller can wipe everything collected so far even
    when a later entry turns out to be malformed.
    """
    raw_keys = manifest_obj.get(b"keys", [])
    if not isinstance(raw_keys, list):
        raise VaultFormatError("legacy manifest 'keys' is not a list")
    for key_entry in raw_keys:
        if not isinstance(key_entry, dict):
            raise VaultFormatError("legacy manifest key entry is not a map")
        if b"public_key_armored" not in key_entry:
            continue
        pub = key_entry.pop(b"public_key_armored")
        priv = key_entry.pop(b"private_key_armored", None)
        if not isinstance(pub, bytes):
            raise VaultFormatError("legacy public key armor is not bytes")
        if priv is not None and not isinstance(priv, bytes):
            raise VaultFormatError("legacy private key armor is not bytes")
        fp_raw = key_entry.get(b"fingerprint")
        fp = fp_raw.decode("utf-8") if isinstance(fp_raw, bytes) else fp_raw
        if not isinstance(fp, str):
            raise VaultFormatError("legacy manifest key entry missing fingerprint")
        out.append((fp, pub, priv))


def _replace_with_segmented_payload(
    payload: bytearray,
    manifest: VaultManifest,
    collected_material: list[tuple[str, bytes, bytes | None]],
) -> int:
    """Rebuild ``payload`` in place into the modern segmented form.

    Returns the key-stream offset (one past the manifest segment) so the
    caller's slice walk works unchanged.
    """
    manifest_bytes = _serialise_manifest(manifest)
    manifest_len = len(manifest_bytes)
    new_payload: bytearray | None = None
    try:
        new_payload = bytearray(_U32.pack(manifest_len))
        new_payload.extend(manifest_bytes)
        for fp, pub, priv in collected_material:
            _append_key_material(new_payload, fingerprint=fp, public_key=pub, private_key=priv)
        # Update the original payload bytearray in-place.
        zero_mutable_buffer(payload)
        payload.clear()
        payload.extend(new_payload)
    finally:
        _zero_bytes_object(manifest_bytes)
        if new_payload is not None:
            zero_mutable_buffer(new_payload)
    return _U32.size + manifest_len


def _deserialise_segmented_payload(
    payload: bytearray,
) -> tuple[VaultManifest, dict[str, _KeySlice]]:
    # Heuristic: if the first byte is a msgpack map (0x80-0x8f), this is a legacy
    # vault without the 4-byte length prefix; rebuild it into the modern form.
    if not payload:
        raise VaultFormatError("vault payload is empty")
    if 0x80 <= payload[0] <= 0x8F:
        manifest, offset = _rebuild_legacy_segmented_payload(payload)
    else:
        view = memoryview(payload)
        manifest_len, offset = _read_u32(view, 0)
        manifest_end = offset + manifest_len
        if manifest_end > len(view):
            raise VaultFormatError("vault manifest segment is truncated")
        manifest = _deserialise_manifest(view[offset:manifest_end])
        offset = manifest_end

    view = memoryview(payload)
    key_slices: dict[str, _KeySlice] = {}
    for entry in manifest.keys:
        key_slice, offset = _read_key_slice(view, offset, entry)
        key_slices[entry.fingerprint] = key_slice
    if offset != len(view):
        raise VaultFormatError("vault key stream has trailing data")
    return manifest, key_slices


def _read_key_slice(
    view: memoryview, offset: int, entry: VaultKeyEntry
) -> tuple[_KeySlice, int]:
    """Walk one key's segment (fingerprint + public + private) and validate it."""
    if offset + _FINGERPRINT_BYTES > len(view):
        raise VaultFormatError("vault key stream is truncated")
    fingerprint = bytes(view[offset : offset + _FINGERPRINT_BYTES]).hex().upper()
    offset += _FINGERPRINT_BYTES

    public_len, offset = _read_u32(view, offset)
    if public_len < 1 or public_len > MAX_VAULT_ARMOR_LENGTH:
        raise VaultFormatError("public key segment length is invalid")
    public_start, public_end = offset, offset + public_len
    if public_end > len(view):
        raise VaultFormatError("public key segment is truncated")
    offset = public_end

    private_len, offset = _read_u32(view, offset)
    if private_len > MAX_VAULT_ARMOR_LENGTH:
        raise VaultFormatError("private key segment length is invalid")
    private_start, private_end = offset, offset + private_len
    if private_end > len(view):
        raise VaultFormatError("private key segment is truncated")
    offset = private_end

    if fingerprint != entry.fingerprint:
        raise VaultFormatError("key stream fingerprint order mismatch")
    if entry.has_private_key and private_len < 1:
        raise VaultFormatError("private key entry is missing private key material")
    return _KeySlice(public_start, public_end, private_start, private_end), offset


def _validate_import_kdf(params: KDFParams) -> None:
    if params.time_cost < MIN_TIME_COST or params.memory_cost < MIN_MEMORY_COST_KB:
        raise VaultFormatError("vault KDF parameters are below the import safety floor")
    if (
        params.time_cost > MAX_IMPORT_TIME_COST
        or params.memory_cost > MAX_IMPORT_MEMORY_COST_KB
        or params.parallelism > MAX_IMPORT_PARALLELISM
    ):
        raise VaultFormatError("vault KDF parameters exceed import safety limits")


def _acquire_write_lock(target_path: Path) -> FileLock:
    try:
        lock = FileLock(target_path, exclusive=True, timeout=5.0)
        lock.acquire()
        return lock
    except FileLockTimeoutError as exc:
        raise VaultServiceError(f"another process is writing to {target_path}") from exc


def _encrypt_payload(
    plaintext: bytearray,
    master_passphrase: SecureBytes,
    *,
    params: KDFParams,
    cipher: CipherAlgorithm,
) -> bytes:
    """Derive the vault key and pack ``plaintext`` into an encrypted binary frame.

    ``plaintext`` is zeroed as soon as the ciphertext exists.
    """
    salt = generate_salt(params.salt_len)
    nonce = generate_nonce()
    header = _build_header(cipher=cipher, salt=salt, nonce=nonce, params=params)

    with derive_key(master_passphrase, salt, params) as vault_key:
        frame, header_bytes = vault_pack(header, b"")
        ciphertext = aead_encrypt(
            plaintext=plaintext,
            key=vault_key,
            nonce=nonce,
            associated_data=header_bytes,
            cipher=cipher,
        )
        zero_mutable_buffer(plaintext)
        # Repack with the real ciphertext now that we have it. The header
        # bytes are deterministic, so the second pack yields the same
        # AAD bytes used during encryption.
        frame, _ = vault_pack(header, ciphertext)
    return frame


def _encrypt_payload_with_slots(
    plaintext: bytearray,
    master_passphrase: SecureBytes | None,
    *,
    params: KDFParams,
    cipher: CipherAlgorithm,
    wrap_for_keys: Callable[[SecureBytes], tuple[VaultKeySlot, ...]],
) -> bytes:
    """Encrypt ``plaintext`` under a random file key wrapped into several slots.

    The passphrase slot comes first when there is one: it is the fallback that
    keeps a lost or broken token from taking the backup with it. Omitting it
    yields a token-only vault, which the caller must have had confirmed.
    ``wrap_for_keys`` adds the OpenPGP slots (one per smartcard key) and is
    injected so this function stays free of the GPG subprocess.

    ``plaintext`` is zeroed as soon as the ciphertext exists.
    """
    nonce = generate_nonce()
    with generate_file_key() as file_key:
        passphrase_slots = (
            ()
            if master_passphrase is None
            else (wrap_with_passphrase(file_key, master_passphrase, params=params, cipher=cipher),)
        )
        slots = (*passphrase_slots, *wrap_for_keys(file_key))
        if not slots:  # pragma: no cover - callers reject this earlier
            raise VaultServiceError("a vault needs at least one unlock method")
        if len(slots) > MAX_VAULT_KEY_SLOTS:
            raise VaultServiceError("too many unlock methods for one vault")
        header = VaultHeader(
            version=VAULT_FORMAT_VERSION_SLOTS,
            cipher=CipherParams(
                algorithm=cipher,
                nonce_b64=base64.b64encode(nonce).decode("ascii"),
            ),
            key_slots=slots,
        )
        _frame, header_bytes = vault_pack(header, b"")
        ciphertext = aead_encrypt(
            plaintext=plaintext,
            key=file_key,
            nonce=nonce,
            associated_data=header_bytes,
            cipher=cipher,
        )
        zero_mutable_buffer(plaintext)
        frame, _ = vault_pack(header, ciphertext)
    return frame


def _unwrap_passphrase_slot(
    header: VaultHeader,
    master_passphrase: SecureBytes,
    *,
    cipher: CipherAlgorithm,
) -> SecureBytes:
    """Recover a v3 vault's file key from the first passphrase slot that opens.

    Slots are tried in order; a slot whose KDF parameters are outside the import
    safety limits is skipped rather than allowed to allocate on our behalf.
    """
    slots = header.slots_of(VaultSlotType.PASSPHRASE)
    if not slots:
        raise VaultServiceError("this vault cannot be opened with a passphrase")
    last_error: Exception | None = None
    for slot in slots:
        if slot.kdf is None:
            continue
        slot_params = slot.kdf.to_params()
        try:
            _validate_import_kdf(slot_params)
            return unwrap_with_passphrase(
                slot, master_passphrase, params=slot_params, cipher=cipher
            )
        except (DecryptionError, VaultFormatError) as exc:
            last_error = exc
    raise last_error or DecryptionError("no key slot accepted this passphrase")


def _unlock_slot_label(key: KeyInfo) -> str:
    """Human label stored with an OpenPGP slot, e.g. ``YubiKey 12345678 · Alice``."""
    return f"{key.storage_label} · {key.primary_user_id}"[:MAX_VAULT_SLOT_LABEL_LENGTH]


def _write_vault_files(target_path: Path, frame: bytes) -> str:
    """Atomically write the vault frame and its SHA-256 sidecar; return the digest."""
    atomic_write_bytes(target_path, frame, mode=0o600)
    sha = hashlib.sha256(frame).hexdigest()
    atomic_write_bytes(
        target_path.with_name(target_path.name + ".sha256"),
        f"{sha}  {target_path.name}\n".encode(),
        mode=0o600,
    )
    return sha


def _read_vault_bytes(src: Path) -> bytes:
    with FileLock(src, exclusive=False, timeout=5.0), src.open("rb") as fh:
        data = fh.read(MAX_VAULT_FRAME_SIZE + 1)
    if len(data) > MAX_VAULT_FRAME_SIZE:
        raise VaultServiceError("vault file is too large")
    return data


def _read_sidecar_digest(sidecar: Path) -> str:
    with sidecar.open("rb") as _f:
        raw = _f.read(256)
    parts = raw.decode("ascii", errors="strict").split()
    if not parts:
        raise VaultServiceError("vault checksum sidecar is empty")
    digest = parts[0].lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise VaultServiceError("vault checksum sidecar is malformed")
    return digest


class VaultService:
    """Stateless façade over the vault create / open flows."""

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

    # ------------------------------------------------------------------- create

    def create(
        self,
        *,
        target_path: Path,
        master_passphrase: SecureBytes | None = None,
        gpg_passphrases: dict[str, SecureBytes],
        fingerprints: Iterable[str],
        description: str = "",
        created_by: str = "",
        cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305,
        kdf_params: KDFParams | None = None,
        unlock_key_fingerprints: Sequence[str] = (),
    ) -> VaultDescriptor:
        """Build a vault from the supplied key fingerprints.

        `gpg_passphrases` maps each fingerprint to its GPG passphrase.
        Stub (smartcard) keys that have no private key to export do not need
        an entry in the dict.

        `unlock_key_fingerprints` names GPG keys — typically the encryption key
        on a YubiKey — that may open the finished vault in addition to the master
        passphrase. Supplying any switches the file to format version 3, where a
        random payload key is wrapped once per unlock method.

        `master_passphrase` may be omitted *only* when unlock keys are given, and
        the result is a vault whose sole key is on those tokens: lose them all
        and the backup is gone for good. Callers must confirm that with the user
        first — the normal path passes both, so the passphrase keeps working if
        a token is lost.

        Order of operations (planv2.md §4.6):
          1. Acquire an exclusive file lock on the target.
          2. Validate fingerprints.
          3. Export private keys via the GPG service (per-key passphrase).
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
        unlock_fps = tuple(validate_fingerprint(fp) for fp in unlock_key_fingerprints)
        if master_passphrase is None and not unlock_fps:
            raise VaultServiceError(
                "a vault needs a master passphrase, an unlock key, or both"
            )

        params = kdf_params or high_memory_params()
        target_path = Path(target_path)
        reject_symlink(target_path)
        target_path = target_path.resolve()
        ensure_dir(target_path.parent)

        lock = _acquire_write_lock(target_path)
        try:
            collected = self._collect_entries(fps, gpg_passphrases)
            entries = tuple(item.entry for item in collected)

            manifest = VaultManifest(
                created_by=created_by,
                created_at=_utc_now(),
                app_version=APP_VERSION,
                description=description,
                keys=entries,
            )
            plaintext = _serialise_segmented_payload(collected, manifest)
            if unlock_fps:
                frame = _encrypt_payload_with_slots(
                    plaintext,
                    master_passphrase,
                    params=params,
                    cipher=cipher,
                    wrap_for_keys=lambda file_key: self._wrap_for_keys(file_key, unlock_fps),
                )
            elif master_passphrase is not None:
                frame = _encrypt_payload(
                    plaintext, master_passphrase, params=params, cipher=cipher
                )
            else:  # pragma: no cover - rejected above
                raise VaultServiceError("no unlock method for this vault")
            sha = _write_vault_files(target_path, frame)

            self._audit.emit(
                "vault_created",
                outcome=OUTCOME_OK,
                path=str(target_path),
                key_count=len(entries),
                cipher=cipher.value,
                sha256=sha,
                unlock_key_count=len(unlock_fps),
            )
            if self._metadata is not None:
                self._metadata.add_vault_record(
                    str(target_path),
                    key_count=len(entries),
                    description=description,
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
        self, fingerprints: tuple[str, ...], gpg_passphrases: dict[str, SecureBytes]
    ) -> tuple[_CollectedEntry, ...]:
        return tuple(self._collect_entry(fp, gpg_passphrases) for fp in fingerprints)

    def _collect_entry(
        self, fp: str, gpg_passphrases: dict[str, SecureBytes]
    ) -> _CollectedEntry:
        try:
            key = self._gpg.find_key(fp)
        except GPGKeyNotFoundError as exc:
            raise VaultServiceError(f"key {fp} not in keyring") from exc

        public_key = self._gpg.export_public_key(fp).encode("utf-8")
        private_key = self._export_private_for_vault(fp, key, gpg_passphrases)
        has_private = private_key is not None

        entry = VaultKeyEntry(
            fingerprint=fp,
            user_ids=key.user_ids,
            has_private_key=has_private,
            is_stub=key.is_stub or (not has_private and key.has_private_key),
            created_at=key.created_at,
            expires_at=key.expires_at,
        )
        return _CollectedEntry(entry=entry, public_key=public_key, private_key=private_key)

    def _export_private_for_vault(
        self, fp: str, key: KeyInfo, gpg_passphrases: dict[str, SecureBytes]
    ) -> bytes | None:
        """Export the private key armor, or None for public-only keys.

        Smartcard stubs cannot have their private parts exported and are
        skipped up front; GPG error 67108875 at export time means the same and
        downgrades the key to public-only.
        """
        if not key.has_private_key or key.is_stub:
            self._audit.emit(
                "key_exported_public",
                outcome=OUTCOME_OK,
                fingerprint=fp,
                is_stub=str(key.is_stub),
            )
            return None

        key_pw = gpg_passphrases.get(fp)
        if key_pw is None:
            raise VaultServiceError(f"no passphrase provided for private key {fp[-16:]}")
        try:
            private_key = self._gpg.export_private_key(fp, key_pw).encode("utf-8")
        except GPGPassphraseError as exc:
            if "67108875" not in str(exc):
                raise
            self._audit.emit(
                "key_exported_public",
                outcome=OUTCOME_OK,
                fingerprint=fp,
                is_stub="True",
                reason="smartcard_export_unsupported",
            )
            return None
        self._audit.emit("key_exported_private", outcome=OUTCOME_OK, fingerprint=fp)
        return private_key

    # --------------------------------------------------------------------- open

    def unlock_info(self, source_path: Path) -> VaultUnlockInfo:
        """Report how a vault can be unlocked, without touching its contents.

        Only the (unencrypted, AAD-bound) header is parsed, so the import view
        can offer "unlock with your token" before any credential is entered.
        """
        src = Path(source_path).resolve()
        if not src.exists():
            raise VaultServiceError(f"vault file does not exist: {src}")
        frame = vault_unpack(_read_vault_bytes(src))
        header = frame.header
        if not header.uses_key_slots:
            return VaultUnlockInfo(version=header.version, accepts_passphrase=True)
        return VaultUnlockInfo(
            version=header.version,
            accepts_passphrase=bool(header.slots_of(VaultSlotType.PASSPHRASE)),
            smartcard_slots=tuple(
                VaultUnlockSlot(fingerprint=slot.fingerprint or "", label=slot.label)
                for slot in header.slots_of(VaultSlotType.OPENPGP)
            ),
        )

    def preview(
        self,
        *,
        source_path: Path,
        master_passphrase: SecureBytes | None = None,
        smartcard_pin: SecureBytes | None = None,
        skip_checksum: bool = False,
    ) -> VaultPreview:
        """Decrypt the manifest and return a read-only preview.

        The local keyring is *not* modified — use `import_keys` to commit a
        subset of the preview into the keyring. Supply either the master
        passphrase or, for a vault with a smartcard slot, the card PIN.
        """
        opened = self._open(
            source_path=source_path,
            master_passphrase=master_passphrase,
            smartcard_pin=smartcard_pin,
            skip_checksum=skip_checksum,
        )
        try:
            return VaultPreview(
                path=Path(source_path).resolve(),
                created_at=opened.manifest.created_at,
                app_version=opened.manifest.app_version,
                description=opened.manifest.description,
                keys=opened.manifest.keys,
            )
        finally:
            opened.close()

    def import_keys(
        self,
        *,
        source_path: Path,
        master_passphrase: SecureBytes | None = None,
        smartcard_pin: SecureBytes | None = None,
        fingerprints: Iterable[str] | None = None,
        skip_checksum: bool = False,
    ) -> list[str]:
        """Decrypt and import (a subset of) the vault's keys into the local keyring.

        If `fingerprints` is None, every key in the manifest is imported.
        Returns the list of fingerprints that were imported successfully.
        """
        opened = self._open(
            source_path=source_path,
            master_passphrase=master_passphrase,
            smartcard_pin=smartcard_pin,
            skip_checksum=skip_checksum,
        )
        try:
            wanted = (
                {validate_fingerprint(fp) for fp in fingerprints}
                if fingerprints is not None
                else {entry.fingerprint for entry in opened.manifest.keys}
            )

            imported: list[str] = []
            for entry in opened.manifest.keys:
                if entry.fingerprint not in wanted:
                    continue
                if self._import_entry(opened, entry):
                    imported.append(entry.fingerprint)

            self._audit.emit(
                "vault_imported",
                outcome=OUTCOME_OK,
                path=str(opened.src_path),
                key_count=len(imported),
            )
            return imported
        finally:
            opened.close()

    # ----------------------------------------------------------------- internal

    def _import_entry(self, opened: _OpenedVault, entry: VaultKeyEntry) -> bool:
        """Import one vault entry into the keyring; True if its key landed."""
        armored = opened.key_material(entry.fingerprint)
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
        finally:
            armored.release()

        # Remove any smuggled keys that were not in the user's selection.
        for smuggled_fp in set(results) - {entry.fingerprint}:
            remove_smuggled_key(self._gpg, self._audit, smuggled_fp, including_secret=True)
        self._audit.emit(
            "key_imported",
            outcome=OUTCOME_OK,
            fingerprint=entry.fingerprint,
            has_private_key=entry.has_private_key,
        )
        return entry.fingerprint in results

    def _open(
        self,
        *,
        source_path: Path,
        master_passphrase: SecureBytes | None = None,
        smartcard_pin: SecureBytes | None = None,
        skip_checksum: bool = False,
    ) -> _OpenedVault:
        if master_passphrase is None and smartcard_pin is None:
            raise VaultServiceError("a master passphrase or a smartcard PIN is required")
        src = Path(source_path).resolve()
        if not src.exists():
            raise VaultServiceError(f"vault file does not exist: {src}")

        data = _read_vault_bytes(src)
        try:
            frame = vault_unpack(data)
        except VaultFormatError:
            self._emit_import_failed(src, reason="format")
            raise

        plaintext = self._decrypt_frame(
            frame, master_passphrase, src, smartcard_pin=smartcard_pin
        )
        try:
            if not skip_checksum:
                self._verify_sidecar(src, data)
            manifest, key_slices = _deserialise_segmented_payload(plaintext)
            # NONCE_LEN sanity check defends against header tampering that survives the
            # AEAD (it should never happen — AAD covers everything — but it's cheap).
            if len(frame.header.cipher.nonce) != NONCE_LEN:
                raise VaultFormatError("vault nonce length mismatch")
            return _OpenedVault(manifest, src, plaintext, key_slices)
        except VaultFormatError:
            # The frame decrypted but its payload is malformed — record it like
            # the other import failure modes so the audit trail stays complete.
            zero_mutable_buffer(plaintext)
            self._emit_import_failed(src, reason="payload")
            raise
        except Exception:
            zero_mutable_buffer(plaintext)
            raise

    def _decrypt_frame(
        self,
        frame: UnpackedFrame,
        master_passphrase: SecureBytes | None,
        src: Path,
        *,
        smartcard_pin: SecureBytes | None = None,
    ) -> bytearray:
        """Recover the vault key and decrypt the frame into a zeroable buffer."""
        with self._vault_key(frame, master_passphrase, smartcard_pin, src) as vault_key:
            try:
                plaintext_bytes = aead_decrypt(
                    ciphertext=frame.ciphertext,
                    key=vault_key,
                    nonce=frame.header.cipher.nonce,
                    associated_data=frame.header_bytes,
                    cipher=frame.header.cipher.algorithm,
                )
            except DecryptionError:
                self._emit_import_failed(src, reason="decryption")
                raise

        plaintext = bytearray(plaintext_bytes)
        _zero_bytes_object(plaintext_bytes)
        return plaintext

    def _vault_key(
        self,
        frame: UnpackedFrame,
        master_passphrase: SecureBytes | None,
        smartcard_pin: SecureBytes | None,
        src: Path,
    ) -> SecureBytes:
        """Return the payload key for this frame, whichever way it is protected.

        A v2 vault derives it from the passphrase. A v3 vault unwraps it from a
        key slot: the smartcard slots when a PIN was supplied, the passphrase
        slots otherwise.
        """
        header = frame.header
        if not header.uses_key_slots:
            if header.kdf is None:  # pragma: no cover - the model forbids this
                raise VaultFormatError("vault header is missing KDF parameters")
            if master_passphrase is None:
                raise VaultServiceError(
                    "this vault predates smartcard unlocking — enter its master passphrase"
                )
            kdf_params = header.kdf.to_params()
            _validate_import_kdf(kdf_params)
            return derive_key(master_passphrase, header.kdf.salt, kdf_params)

        if smartcard_pin is not None:
            return self._unwrap_openpgp_slot(header, smartcard_pin, src)
        if master_passphrase is None:  # pragma: no cover - guarded in _open
            raise VaultServiceError("a master passphrase or a smartcard PIN is required")
        try:
            return _unwrap_passphrase_slot(
                header, master_passphrase, cipher=header.cipher.algorithm
            )
        except DecryptionError:
            self._emit_import_failed(src, reason="decryption")
            raise

    def _unwrap_openpgp_slot(
        self, header: VaultHeader, smartcard_pin: SecureBytes, src: Path
    ) -> SecureBytes:
        """Open the first OpenPGP slot the token accepts and return the file key."""
        slots = header.slots_of(VaultSlotType.OPENPGP)
        if not slots:
            raise VaultServiceError(
                "this vault has no smartcard unlock method — open it with its master passphrase"
            )
        last_error: Exception | None = None
        for slot in slots:
            try:
                plaintext, _signer, _status, _decrypted_with = self._gpg.decrypt(
                    slot.wrapped_key, passphrase=smartcard_pin
                )
            except (GPGCardError, GPGPassphraseError, GPGProcessError) as exc:
                last_error = exc
                continue
            return file_key_from_bytes(plaintext)
        self._emit_import_failed(src, reason="smartcard")
        raise last_error or DecryptionError("no smartcard key slot could be opened")

    def _wrap_for_keys(
        self, file_key: SecureBytes, fingerprints: Sequence[str]
    ) -> tuple[VaultKeySlot, ...]:
        """Seal the file key to each additional unlock key (usually a token key)."""
        slots: list[VaultKeySlot] = []
        for fp in fingerprints:
            key = self._gpg.find_key(fp)
            if key.is_revoked:
                raise VaultServiceError("a revoked key cannot be used to unlock a vault")
            if key.is_expired:
                raise VaultServiceError("an expired key cannot be used to unlock a vault")
            raw = file_key.to_bytes()
            try:
                armored = self._gpg.encrypt(
                    raw,
                    recipient_fingerprints=[fp],
                    # The user picked one of their own keys out of the local
                    # keyring, so the ownertrust of that key is not a meaningful
                    # gate here — an untrusted-but-selected key would otherwise
                    # make the vault unopenable by the token that holds it.
                    always_trust=True,
                )
            finally:
                _zero_bytes_object(raw)
            slots.append(
                openpgp_slot(
                    armored.encode("utf-8"),
                    fingerprint=key.fingerprint,
                    label=_unlock_slot_label(key),
                )
            )
        return tuple(slots)

    def _verify_sidecar(self, src: Path, data: bytes) -> None:
        """Check the .sha256 sidecar — best-effort: a missing sidecar is fine."""
        sidecar = src.with_name(src.name + ".sha256")
        if not sidecar.exists():
            return
        expected = _read_sidecar_digest(sidecar)
        actual = hashlib.sha256(data).hexdigest().lower()
        if not hmac.compare_digest(expected, actual):
            self._emit_import_failed(src, reason="checksum")
            raise VaultChecksumMismatchError(
                f"vault checksum mismatch: expected {expected[:16]}…"
            )

    def _emit_import_failed(self, src: Path, *, reason: str) -> None:
        self._audit.emit(
            "vault_import_failed",
            outcome=OUTCOME_FAILED,
            path=str(src),
            reason=reason,
        )
