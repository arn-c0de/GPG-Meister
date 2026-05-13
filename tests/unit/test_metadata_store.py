from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from gpg_meister.storage.metadata_store import MetadataStore


def test_upsert_and_get_key(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        store.upsert_key("AAAA" * 10, label="test key")
        row = store.get_key("AAAA" * 10)
    assert row is not None
    assert row["label"] == "test key"
    assert row["import_timestamp"] is not None
    assert row["last_used_timestamp"] is None


def test_upsert_updates_label(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        fp = "BBBB" * 10
        store.upsert_key(fp, label="old")
        store.upsert_key(fp, label="new")
        row = store.get_key(fp)
    assert row is not None
    assert row["label"] == "new"


def test_touch_key_sets_timestamp(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        fp = "CCCC" * 10
        store.upsert_key(fp)
        store.touch_key(fp)
        row = store.get_key(fp)
    assert row is not None
    assert row["last_used_timestamp"] is not None


def test_delete_key(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        fp = "DDDD" * 10
        store.upsert_key(fp, label="to delete")
        store.delete_key(fp)
        assert store.get_key(fp) is None


def test_list_keys_order(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        for i in range(3):
            store.upsert_key(f"{i:040X}", label=f"key{i}")
        rows = store.list_keys()
    assert len(rows) == 3


def test_vault_record_roundtrip(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        rid = store.add_vault_record("backup.gpgvault", key_count=2, description="home")
        records = store.list_vault_records()
    assert rid >= 1
    assert len(records) == 1
    assert records[0]["filename"] == "backup.gpgvault"
    assert records[0]["key_count"] == 2
    assert records[0]["description"] == "home"


def test_latest_vault_timestamp_empty(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        assert store.latest_vault_timestamp() is None


def test_latest_vault_timestamp_after_add(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        store.add_vault_record("v1.gpgvault", key_count=1)
        ts = store.latest_vault_timestamp()
    assert ts is not None
    assert "T" in ts


def test_preference_set_and_get(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        store.set_preference("theme", "dark")
        assert store.get_preference("theme") == "dark"


def test_preference_overwrite(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        store.set_preference("theme", "light")
        store.set_preference("theme", "dark")
        assert store.get_preference("theme") == "dark"


def test_preference_missing_default(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        assert store.get_preference("nonexistent") is None
        assert store.get_preference("nonexistent", "fallback") == "fallback"


def test_preference_delete(tmp_path: Path) -> None:
    with MetadataStore(tmp_path / "meta.sqlite3") as store:
        store.set_preference("x", "y")
        store.delete_preference("x")
        assert store.get_preference("x") is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_db_file_is_mode_0600(tmp_path: Path) -> None:
    path = tmp_path / "meta.sqlite3"
    with MetadataStore(path):
        pass
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_persists_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "meta.sqlite3"
    with MetadataStore(path) as store:
        store.upsert_key("EEEE" * 10, label="persistent")
    with MetadataStore(path) as store:
        row = store.get_key("EEEE" * 10)
    assert row is not None
    assert row["label"] == "persistent"
