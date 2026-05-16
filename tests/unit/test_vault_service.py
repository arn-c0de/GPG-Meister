from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from gpg_meister.models.vault import VaultKeyEntry, VaultManifest
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.vault_service import VaultService


class _Audit:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, object]]] = []

    def emit(self, event: str, **payload: object) -> None:
        self.events.append((event, payload))


class _GPG:
    def __init__(self, returned_fingerprints: list[str]) -> None:
        self.returned_fingerprints = returned_fingerprints
        self.deleted: list[tuple[str, bool]] = []

    def import_key(self, _armored: str) -> list[str]:
        return self.returned_fingerprints

    def delete_key(self, fingerprint: str, *, including_secret: bool = False) -> None:
        self.deleted.append((fingerprint, including_secret))


def test_import_keys_removes_smuggled_keys(monkeypatch, tmp_path: Path) -> None:
    selected_fp = "A" * 40
    smuggled_fp = "B" * 40
    source_path = tmp_path / "backup.gpgm"
    entry = VaultKeyEntry(
        fingerprint=selected_fp,
        user_ids=("Alice <alice@example.org>",),
        public_key_armored="-----BEGIN PGP PUBLIC KEY BLOCK-----\nselected\n",
        private_key_armored=None,
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
        lambda **_kwargs: (manifest, source_path),
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
