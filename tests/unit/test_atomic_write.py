from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from gpg_meister.storage.atomic_write import AtomicWriter, atomic_write_bytes


def _temp_artifacts(directory: Path) -> list[Path]:
    return [p for p in directory.iterdir() if p.name.endswith(".tmp") or ".tmp" in p.name]


def test_atomic_write_creates_file(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    atomic_write_bytes(target, b"hello")
    assert target.read_bytes() == b"hello"


def test_atomic_write_overwrites_existing(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    target.write_bytes(b"old")
    atomic_write_bytes(target, b"new")
    assert target.read_bytes() == b"new"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_atomic_write_applies_mode(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    atomic_write_bytes(target, b"data", mode=0o600)
    mode = stat.S_IMODE(target.stat().st_mode)
    # umask may further restrict; the file must NOT be group/world readable.
    assert mode & 0o077 == 0
    assert mode & 0o600 == 0o600


def test_atomic_write_does_not_leave_tmp_on_success(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    atomic_write_bytes(target, b"hello")
    assert _temp_artifacts(tmp_path) == []


def test_atomic_write_cleans_tmp_on_replace_failure(tmp_path: Path) -> None:
    """If os.replace raises, the target must be untouched and the tmp removed."""
    target = tmp_path / "out.bin"
    target.write_bytes(b"original")

    with (
        patch("gpg_meister.storage.atomic_write.os.replace", side_effect=OSError("boom")),
        pytest.raises(OSError, match="boom"),
    ):
        atomic_write_bytes(target, b"replacement")

    assert target.read_bytes() == b"original"
    assert _temp_artifacts(tmp_path) == []


def test_atomic_write_rejects_missing_parent(tmp_path: Path) -> None:
    target = tmp_path / "no-such-dir" / "out.bin"
    with pytest.raises(FileNotFoundError):
        atomic_write_bytes(target, b"x")


def test_writer_context_commits_on_clean_exit(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    with AtomicWriter(target) as fh:
        fh.write(b"part1-")
        fh.write(b"part2")
    assert target.read_bytes() == b"part1-part2"
    assert _temp_artifacts(tmp_path) == []


def test_writer_context_rolls_back_on_exception(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    target.write_bytes(b"original")

    with pytest.raises(RuntimeError, match="kaboom"), AtomicWriter(target) as fh:
        fh.write(b"partial")
        raise RuntimeError("kaboom")

    assert target.read_bytes() == b"original"
    assert _temp_artifacts(tmp_path) == []


def test_writer_does_not_create_target_if_target_did_not_exist_and_failed(
    tmp_path: Path,
) -> None:
    target = tmp_path / "out.bin"
    with pytest.raises(RuntimeError), AtomicWriter(target) as fh:
        fh.write(b"partial")
        raise RuntimeError("nope")
    assert not target.exists()
    assert _temp_artifacts(tmp_path) == []


def test_concurrent_writes_do_not_collide_on_tmp_name(tmp_path: Path) -> None:
    """Two writers targeting the same file must each pick a distinct tmp suffix."""
    target = tmp_path / "out.bin"

    # Start the first writer but do not commit until the second has opened.
    a = AtomicWriter(target).__enter__()
    b = AtomicWriter(target).__enter__()
    try:
        # Each writer must have its own distinct tmp file.
        artifacts = sorted(_temp_artifacts(tmp_path))
        assert len(artifacts) == 2
        assert artifacts[0] != artifacts[1]

        a.write(b"AAA")
        b.write(b"BBB")
    finally:
        a.__exit__(None, None, None)
        b.__exit__(None, None, None)

    # The last commit wins; only the final target exists.
    assert target.exists()
    assert _temp_artifacts(tmp_path) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_atomic_write_mode_after_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "out.bin"
    target.write_bytes(b"old")
    os.chmod(target, 0o644)
    atomic_write_bytes(target, b"new", mode=0o600)
    mode = stat.S_IMODE(target.stat().st_mode)
    # After replace, the new file's permissions take effect.
    assert mode & 0o077 == 0
