from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo
from gpg_meister.services.key_service import KeyService
from gpg_meister.storage.audit_log import AuditLog
from gpg_meister.storage.metadata_store import MetadataStore


def _key(fingerprint: str) -> KeyInfo:
    return KeyInfo(
        fingerprint=fingerprint,
        user_ids=("Alice <alice@example.org>",),
        algorithm=KeyAlgorithm.EDDSA,
        length=255,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


class _FakeGPGService:
    def __init__(self, keys: list[KeyInfo]) -> None:
        self._keys = {key.fingerprint: key for key in keys}
        self._generated = 0

    def list_keys(self, *, secret: bool = False) -> list[KeyInfo]:
        return list(self._keys.values())

    def find_key(self, fingerprint: str) -> KeyInfo:
        return self._keys[fingerprint]

    def generate_key(
        self,
        *,
        name: str,
        email: str,
        algorithm: KeyAlgorithm,
        length: int,
        expiry: str,
        passphrase: object,
    ) -> str:
        self._generated += 1
        fingerprint = f"{self._generated:040X}"
        self._keys[fingerprint] = KeyInfo(
            fingerprint=fingerprint,
            user_ids=(f"{name} <{email}>",),
            algorithm=algorithm,
            length=length,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        return fingerprint


def test_list_keys_merges_user_context_from_metadata(tmp_path: Path) -> None:
    key = _key("A" * 40)
    gpg = _FakeGPGService([key])
    metadata = MetadataStore(tmp_path / "meta.sqlite3")
    metadata.upsert_key(
        key.fingerprint,
        label="Company Key",
        purpose="Code Signing",
        platform="GitHub",
        notes="Release pipeline",
    )
    audit = AuditLog(tmp_path / "audit.log")
    service = KeyService(gpg=gpg, audit=audit, metadata=metadata)

    keys = service.list_keys()

    assert len(keys) == 1
    assert keys[0].label == "Company Key"
    assert keys[0].purpose == "Code Signing"
    assert keys[0].platform == "GitHub"
    assert keys[0].notes == "Release pipeline"
    metadata.close()
    audit.close()


def test_update_context_persists_and_returns_enriched_key(tmp_path: Path) -> None:
    key = _key("B" * 40)
    gpg = _FakeGPGService([key])
    metadata = MetadataStore(tmp_path / "meta.sqlite3")
    audit = AuditLog(tmp_path / "audit.log")
    service = KeyService(gpg=gpg, audit=audit, metadata=metadata)

    updated = service.update_context(
        key.fingerprint,
        label="Work",
        purpose="Encryption",
        platform="GitLab",
        notes="Rotates yearly",
    )

    assert updated.label == "Work"
    assert updated.purpose == "Encryption"
    assert updated.platform == "GitLab"
    assert updated.notes == "Rotates yearly"
    assert metadata.get_key(key.fingerprint)["label"] == "Work"
    metadata.close()
    audit.close()


def test_create_persists_optional_context_metadata(tmp_path: Path) -> None:
    gpg = _FakeGPGService([])
    metadata = MetadataStore(tmp_path / "meta.sqlite3")
    audit = AuditLog(tmp_path / "audit.log")
    service = KeyService(gpg=gpg, audit=audit, metadata=metadata)

    from gpg_meister.security.secure_bytes import SecureBytes

    with SecureBytes.from_bytes(b"correct horse battery staple") as passphrase:
        created = service.create(
            name="Alice",
            email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA,
            length=255,
            expiry="2y",
            passphrase=passphrase,
            label="Work Key",
            purpose="Code Signing",
            platform="GitHub",
            notes="Release automation",
        )

    assert created.label == "Work Key"
    assert created.purpose == "Code Signing"
    assert created.platform == "GitHub"
    assert created.notes == "Release automation"
    row = metadata.get_key(created.fingerprint)
    assert row is not None
    assert row["label"] == "Work Key"
    assert row["purpose"] == "Code Signing"
    assert row["platform"] == "GitHub"
    assert row["notes"] == "Release automation"
    metadata.close()
    audit.close()
