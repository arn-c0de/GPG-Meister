from __future__ import annotations

import stat
import sys
from pathlib import Path

import pytest

from gpg_meister.storage.paths import resolve_paths


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only XDG override behaviour")
def test_xdg_overrides_are_honoured(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    paths = resolve_paths()

    assert paths.config_dir == tmp_path / "cfg" / "gpg-meister"
    assert paths.data_dir == tmp_path / "data" / "gpg-meister"
    assert paths.state_dir == tmp_path / "state" / "gpg-meister"
    assert paths.gnupg_home == tmp_path / "data" / "gpg-meister" / "gnupg"
    assert paths.vault_dir == tmp_path / "data" / "gpg-meister" / "vaults"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only XDG override behaviour")
def test_relative_xdg_falls_back_to_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A relative XDG override violates the spec and must be ignored.
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/path")
    monkeypatch.setenv("HOME", str(tmp_path))

    paths = resolve_paths()
    assert paths.config_dir == tmp_path / ".config" / "gpg-meister"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission semantics")
def test_ensure_creates_directories_with_mode_0700(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))

    paths = resolve_paths()
    paths.ensure()

    for path in (paths.config_dir, paths.data_dir, paths.state_dir, paths.gnupg_home):
        assert path.exists()
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o700, f"{path} has mode {oct(mode)}, expected 0o700"


def test_resolve_paths_returns_absolute_paths() -> None:
    paths = resolve_paths()
    assert paths.config_dir.is_absolute()
    assert paths.data_dir.is_absolute()
    assert paths.gnupg_home.is_absolute()
    assert paths.vault_dir.is_absolute()
    assert paths.audit_log.is_absolute()
