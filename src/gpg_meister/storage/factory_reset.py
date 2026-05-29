"""Factory-reset helpers for clearing all local app-managed state.

The reset is intentionally two-phase:

- The running app only writes a small marker file.
- The next startup performs the actual deletion before long-lived handles such as
  SQLite, logs, or the GPG home are opened.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

from gpg_meister.storage.paths import AppPaths
from gpg_meister.storage.permissions import reject_symlink, reject_symlink_tree

_MARKER_NAME = ".factory-reset-pending"


def marker_path(paths: AppPaths) -> str:
    return str(paths.config_dir / _MARKER_NAME)


def _overwrite_file(item: Path, shred: str | None) -> None:
    """Best-effort single-file overwrite before deletion.

    Overwriting is *best-effort only*: on SSDs, copy-on-write filesystems
    (Btrfs/ZFS/APFS) and journalled filesystems the original blocks may survive
    in unreferenced extents, the FTL, or snapshots. True secure erase needs
    full-disk encryption — see :func:`perform_pending_factory_reset`.
    """
    if not item.is_file() or item.is_symlink():
        return
    if shred:
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(  # noqa: S603
                [shred, "-u", "-z", str(item)],
                check=False,
                capture_output=True,
                timeout=10,
            )
        return
    with contextlib.suppress(OSError):
        size = item.stat().st_size
        with item.open("r+b") as f:
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())


def _secure_wipe_sensitive(paths: AppPaths) -> None:
    """Overwrite all secret-bearing files before deletion (best-effort).

    Covers the GPG home (private keys), the metadata DB and its SQLite
    sidecars, the audit and diagnostic logs, and the vault files. See
    :func:`_overwrite_file` for the (significant) limitations.
    """
    shred = shutil.which("shred") if sys.platform == "linux" else None

    gnupg_dir = paths.gnupg_home
    if gnupg_dir.exists():
        reject_symlink_tree(gnupg_dir)
        for item in gnupg_dir.rglob("*"):
            _overwrite_file(item, shred)

    vault_dir = paths.vault_dir
    if vault_dir.exists():
        reject_symlink_tree(vault_dir)
        for item in vault_dir.rglob("*"):
            _overwrite_file(item, shred)

    explicit_files = [
        paths.metadata_db,
        paths.metadata_db.with_name(paths.metadata_db.name + "-wal"),
        paths.metadata_db.with_name(paths.metadata_db.name + "-shm"),
        paths.audit_log,
        paths.audit_log.with_name(paths.audit_log.name + ".tip"),
        paths.diagnostic_log,
    ]
    for item in explicit_files:
        if item.exists():
            _overwrite_file(item, shred)


def request_factory_reset(paths: AppPaths) -> None:
    """Schedule a factory reset for the next app launch."""
    paths.ensure()
    marker = paths.config_dir / _MARKER_NAME
    reject_symlink(marker)
    marker.write_text("pending\n", encoding="utf-8")


def perform_pending_factory_reset(paths: AppPaths) -> bool:
    """Delete all local app-managed state if a reset marker is present.

    Secret-bearing files are overwritten before the directory trees are
    removed. Note that overwriting cannot guarantee erasure on SSD/CoW/
    journalled storage; users who need that guarantee must rely on full-disk
    encryption.
    """
    marker = paths.config_dir / _MARKER_NAME
    reject_symlink(marker)
    if not marker.exists():
        return False

    _secure_wipe_sensitive(paths)
    for directory in (
        paths.state_dir,
        paths.data_dir,
        paths.cache_dir,
        paths.config_dir,
    ):
        if directory.exists():
            reject_symlink_tree(directory)
            if directory.is_symlink():
                raise RuntimeError(f"refusing to delete symlink: {directory}")
            shutil.rmtree(directory)

    paths.ensure()
    return True
