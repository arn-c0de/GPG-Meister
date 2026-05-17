from __future__ import annotations

import os
import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from gpg_meister.models.kdf_params import KDFAlgorithm, KDFParams
from gpg_meister.models.vault import VaultKeyEntry, VaultManifest
from gpg_meister.security.errors import VaultFormatError
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services import vault_service as vault_service_module
from gpg_meister.services.vault_service import (
    VaultService,
    VaultServiceError,
    _CollectedEntry,
    _deserialise_segmented_payload,
    _KeySlice,
    _OpenedVault,
    _serialise_segmented_payload,
    _validate_import_kdf,
)


class _Audit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def emit(self, event: str, **payload: object) -> None:
        self.events.append((event, payload))


class _GPG:
    def __init__(self, returned_fingerprints: list[str]) -> None:
        self.returned_fingerprints = returned_fingerprints
        self.deleted: list[tuple[str, bool]] = []

    def import_key(self, _armored: object) -> list[str]:
        return self.returned_fingerprints

    def delete_key(self, fingerprint: str, *, including_secret: bool = False) -> None:
        self.deleted.append((fingerprint, including_secret))


def test_import_keys_removes_smuggled_keys(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    selected_fp = "A" * 40
    smuggled_fp = "B" * 40
    source_path = tmp_path / "backup.gpgm"
    entry = VaultKeyEntry(
        fingerprint=selected_fp,
        user_ids=("Alice <alice@example.org>",),
        has_private_key=False,
        is_stub=False,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    manifest = VaultManifest(
        created_by="test",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        app_version="test",
        description="",
        keys=(entry,),
    )
    gpg = _GPG([selected_fp, smuggled_fp])
    audit = _Audit()
    service = VaultService(gpg=gpg, audit=audit)  # type: ignore[arg-type]

    monkeypatch.setattr(
        service,
        "_open",
        lambda **_kwargs: _OpenedVault(
            manifest=manifest,
            src_path=source_path,
            plaintext=bytearray(b"public"),
            key_slices={selected_fp: _KeySlice(0, 6, 6, 6)},
        ),
    )

    with SecureBytes.from_bytes(b"master passphrase") as master:
        imported = service.import_keys(
            source_path=source_path,
            master_passphrase=master,
        )

    assert imported == [selected_fp]
    assert gpg.deleted == [(smuggled_fp, True)]
    assert (
        "key_imported",
        {
            "outcome": "warning",
            "fingerprint": smuggled_fp,
            "reason": "smuggled_key_removed",
        },
    ) in audit.events


def test_segmented_payload_keeps_key_material_out_of_manifest() -> None:
    fp = "A" * 40
    entry = VaultKeyEntry(
        fingerprint=fp,
        user_ids=("Alice <alice@example.org>",),
        has_private_key=True,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    manifest = VaultManifest(
        created_by="test",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        app_version="test",
        description="",
        keys=(entry,),
    )
    public_key = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\npublic\n"
    private_key = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nPRIVATE_SECRET\n"

    payload = _serialise_segmented_payload(
        (_CollectedEntry(entry=entry, public_key=public_key, private_key=private_key),),
        manifest,
    )
    manifest_len = struct.unpack_from(">I", payload, 0)[0]
    manifest_segment = payload[4 : 4 + manifest_len]

    assert b"PRIVATE_SECRET" not in manifest_segment
    parsed, key_slices = _deserialise_segmented_payload(payload)

    assert parsed.keys == (entry,)
    key_slice = key_slices[fp]
    assert payload[key_slice.public_start : key_slice.public_end] == public_key
    assert payload[key_slice.private_start : key_slice.private_end] == private_key


def test_open_rejects_oversized_vault_with_bounded_read(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source_path = tmp_path / "oversized.gpgm"
    source_path.write_bytes(b"012345678")
    service = VaultService(gpg=_GPG([]), audit=_Audit())  # type: ignore[arg-type]
    monkeypatch.setattr(vault_service_module, "MAX_VAULT_FRAME_SIZE", 8)

    with (
        SecureBytes.from_bytes(b"master passphrase") as master,
        pytest.raises(VaultServiceError, match="too large"),
    ):
        service.preview(source_path=source_path, master_passphrase=master)


def test_validate_import_kdf_rejects_weak_params() -> None:
    """Floor check must reject params that Pydantic bypasses (defense-in-depth)."""
    weak = KDFParams.model_construct(
        algorithm=KDFAlgorithm.ARGON2ID,
        time_cost=1,
        memory_cost=1024,
        parallelism=1,
        hash_len=32,
        salt_len=16,
    )
    with pytest.raises(VaultFormatError, match="floor"):
        _validate_import_kdf(weak)


def test_validate_import_kdf_accepts_valid_params() -> None:
    from gpg_meister.models.kdf_params import high_memory_params
    _validate_import_kdf(high_memory_params())


def test_create_rejects_symlink_target(tmp_path: Path) -> None:
    target = tmp_path / "target.gpgm"
    target.write_bytes(b"existing")
    link = tmp_path / "backup.gpgm"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")
    service = VaultService(gpg=_GPG([]), audit=_Audit())  # type: ignore[arg-type]

    with (
        SecureBytes.from_bytes(b"master passphrase") as master,
        pytest.raises(RuntimeError, match="symlink"),
    ):
        service.create(
            target_path=link,
            master_passphrase=master,
            gpg_passphrases={},
            fingerprints=["A" * 40],
        )
