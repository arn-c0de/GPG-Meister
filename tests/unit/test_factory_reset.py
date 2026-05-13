from __future__ import annotations

from pathlib import Path

from gpg_meister.storage.factory_reset import perform_pending_factory_reset, request_factory_reset
from gpg_meister.storage.paths import AppPaths


def _paths(root: Path) -> AppPaths:
    return AppPaths(
        config_dir=root / "config",
        data_dir=root / "data",
        state_dir=root / "state",
        cache_dir=root / "cache",
    )


def test_request_factory_reset_writes_marker(tmp_path: Path) -> None:
    paths = _paths(tmp_path)

    request_factory_reset(paths)

    assert (paths.config_dir / ".factory-reset-pending").exists()


def test_perform_pending_factory_reset_clears_app_state_and_recreates_dirs(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.ensure()
    (paths.config_file).write_text("locale = 'en'\n", encoding="utf-8")
    (paths.metadata_db).write_text("db", encoding="utf-8")
    (paths.audit_log).write_text("audit", encoding="utf-8")
    (paths.gnupg_home / "pubring.kbx").write_text("keys", encoding="utf-8")
    (paths.vault_dir / "backup.gpgvault").write_text("vault", encoding="utf-8")
    request_factory_reset(paths)

    changed = perform_pending_factory_reset(paths)

    assert changed is True
    assert paths.config_dir.exists()
    assert paths.data_dir.exists()
    assert paths.state_dir.exists()
    assert paths.cache_dir.exists()
    assert not paths.config_file.exists()
    assert not paths.metadata_db.exists()
    assert not paths.audit_log.exists()
    assert not (paths.gnupg_home / "pubring.kbx").exists()
    assert not (paths.vault_dir / "backup.gpgvault").exists()


def test_perform_pending_factory_reset_is_noop_without_marker(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.ensure()

    changed = perform_pending_factory_reset(paths)

    assert changed is False
