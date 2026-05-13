from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from gpg_meister.models.config import AppConfig, AppearanceMode, Locale
from gpg_meister.models.kdf_params import KDFProfile
from gpg_meister.models.vault import CipherAlgorithm
from gpg_meister.services.config_service import (
    ConfigServiceError,
    load,
    save,
    warn_if_world_readable,
)


def test_load_returns_defaults_when_missing(tmp_path: Path) -> None:
    cfg = load(tmp_path / "config.toml")
    assert cfg == AppConfig()


def test_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    original = AppConfig(
        locale=Locale.DE,
        appearance=AppearanceMode.DARK,
        cipher=CipherAlgorithm.AES_256_GCM,
        kdf_profile=KDFProfile.BALANCED,
        clipboard_clear_seconds=30,
        backup_reminder_days=14,
        high_contrast=True,
        reduce_motion=True,
        require_delete_text_confirmation=False,
    )
    save(original, target)
    reloaded = load(target)
    assert reloaded == original


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_save_applies_mode_0600(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    save(AppConfig(), target)
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode & 0o077 == 0
    assert mode & 0o600 == 0o600


def test_unknown_keys_rejected(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    target.write_text("locale = 'en'\nrogue_key = 42\n", encoding="utf-8")
    with pytest.raises(ConfigServiceError, match="invalid"):
        load(target)


def test_out_of_range_values_rejected(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    target.write_text(
        "locale = 'en'\nclipboard_clear_seconds = 99999\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigServiceError):
        load(target)


def test_malformed_toml_rejected(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    target.write_bytes(b"this is not [toml")
    with pytest.raises(ConfigServiceError):
        load(target)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_warn_if_world_readable_flags_loose_perms(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    save(AppConfig(), target)
    os.chmod(target, 0o644)
    warning = warn_if_world_readable(target)
    assert warning is not None and "config" in warning


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_warn_if_world_readable_silent_on_safe_perms(tmp_path: Path) -> None:
    target = tmp_path / "config.toml"
    save(AppConfig(), target)
    assert warn_if_world_readable(target) is None


def test_warn_if_missing_returns_none(tmp_path: Path) -> None:
    assert warn_if_world_readable(tmp_path / "nope") is None
