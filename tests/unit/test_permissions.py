from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from gpg_meister.storage.permissions import (
    PermissionStatus,
    ensure_dir,
    ensure_file_mode,
    is_safe_for_secrets,
    report,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="Permission semantics differ on Windows"
)


def test_ensure_dir_creates_with_mode_0700(tmp_path: Path) -> None:
    target = tmp_path / "subdir"
    ensure_dir(target)
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o700


def test_ensure_dir_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "subdir"
    ensure_dir(target)
    os.chmod(target, 0o755)
    ensure_dir(target)
    assert stat.S_IMODE(target.stat().st_mode) == 0o700


def test_ensure_file_mode_sets_0600(tmp_path: Path) -> None:
    f = tmp_path / "secret"
    f.write_text("data")
    os.chmod(f, 0o644)
    ensure_file_mode(f)
    assert stat.S_IMODE(f.stat().st_mode) == 0o600


def test_ensure_file_mode_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        ensure_file_mode(tmp_path / "missing")


def test_report_ok_for_private_file(tmp_path: Path) -> None:
    f = tmp_path / "secret"
    f.write_text("data")
    os.chmod(f, 0o600)
    rep = report(f)
    assert rep.status is PermissionStatus.OK
    assert rep.mode == 0o600


def test_report_flags_world_readable(tmp_path: Path) -> None:
    f = tmp_path / "secret"
    f.write_text("data")
    os.chmod(f, 0o644)
    assert report(f).status is PermissionStatus.WORLD_READABLE


def test_report_flags_group_readable(tmp_path: Path) -> None:
    f = tmp_path / "secret"
    f.write_text("data")
    os.chmod(f, 0o640)
    assert report(f).status is PermissionStatus.GROUP_READABLE


def test_report_flags_world_writable(tmp_path: Path) -> None:
    f = tmp_path / "secret"
    f.write_text("data")
    os.chmod(f, 0o666)
    assert report(f).status is PermissionStatus.WORLD_WRITABLE


def test_report_for_missing_file(tmp_path: Path) -> None:
    assert report(tmp_path / "nope").status is PermissionStatus.NOT_FOUND


def test_is_safe_true_when_private(tmp_path: Path) -> None:
    d = tmp_path / "dir"
    ensure_dir(d)
    assert is_safe_for_secrets(d)


def test_is_safe_false_when_world_readable(tmp_path: Path) -> None:
    f = tmp_path / "secret"
    f.write_text("data")
    os.chmod(f, 0o644)
    assert not is_safe_for_secrets(f)
