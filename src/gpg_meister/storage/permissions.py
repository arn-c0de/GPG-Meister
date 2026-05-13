"""File system permission helpers (planv2.md §5.5).

POSIX-focused: enforces mode 0700 on directories and 0600 on sensitive files.
On Windows, the standard NTFS ACL on a user-owned folder under %APPDATA% is
already user-private; this module reports permission status as `windows-acl`
without attempting to enforce a chmod equivalent.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class PermissionStatus(StrEnum):
    OK = "ok"
    GROUP_READABLE = "group_readable"
    WORLD_READABLE = "world_readable"
    GROUP_WRITABLE = "group_writable"
    WORLD_WRITABLE = "world_writable"
    WINDOWS_ACL = "windows_acl"
    NOT_FOUND = "not_found"


@dataclass(frozen=True)
class PermissionReport:
    path: Path
    status: PermissionStatus
    mode: int  # 0 when not applicable (Windows / missing)


def ensure_dir(path: Path, *, mode: int = 0o700) -> None:
    """Create `path` (and parents) and set permissions to `mode` on POSIX.

    Newly created directories are made one-by-one with the requested mode so they
    never transiently appear with broader permissions than intended.
    """
    if sys.platform == "win32":
        path.mkdir(parents=True, exist_ok=True)
        return

    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            break
        current = parent

    for directory in reversed(missing):
        try:
            os.mkdir(directory, mode)
        except FileExistsError:
            if not directory.is_dir():
                raise

    if path.exists() and not path.is_dir():
        raise NotADirectoryError(path)
    os.chmod(path, mode)


def ensure_file_mode(path: Path, *, mode: int = 0o600) -> None:
    """Set permissions of an existing file to `mode` on POSIX. No-op on Windows."""
    if sys.platform == "win32":
        return
    if not path.exists():
        raise FileNotFoundError(path)
    os.chmod(path, mode)


def report(path: Path) -> PermissionReport:
    """Return a permission report. Never raises for missing paths."""
    if not path.exists():
        return PermissionReport(path=path, status=PermissionStatus.NOT_FOUND, mode=0)

    if sys.platform == "win32":
        return PermissionReport(path=path, status=PermissionStatus.WINDOWS_ACL, mode=0)

    mode = stat.S_IMODE(path.stat().st_mode)

    # Most severe issues first.
    if mode & stat.S_IWOTH:
        return PermissionReport(path=path, status=PermissionStatus.WORLD_WRITABLE, mode=mode)
    if mode & stat.S_IWGRP:
        return PermissionReport(path=path, status=PermissionStatus.GROUP_WRITABLE, mode=mode)
    if mode & stat.S_IROTH:
        return PermissionReport(path=path, status=PermissionStatus.WORLD_READABLE, mode=mode)
    if mode & stat.S_IRGRP:
        return PermissionReport(path=path, status=PermissionStatus.GROUP_READABLE, mode=mode)

    return PermissionReport(path=path, status=PermissionStatus.OK, mode=mode)


def is_safe_for_secrets(path: Path) -> bool:
    """True iff the path is not group/world readable or writable on POSIX.

    On Windows, returns True (we trust the NTFS ACL of the user profile).
    """
    rep = report(path)
    if rep.status is PermissionStatus.WINDOWS_ACL:
        return True
    return rep.status is PermissionStatus.OK
