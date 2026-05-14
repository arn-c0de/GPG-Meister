"""GPG binary detection with a hard whitelist (planv2.md §9.2).

The default policy refuses to execute any binary discovered via $PATH unless its
canonical (symlink-resolved) path matches one of the platform whitelist entries.
A user-supplied override path may be accepted only if it is pinned by a stable
SHA-256 hash stored in the application config.

This module performs *no* GPG invocations. It only resolves and validates the
binary path, hashes it, and decides whether it is trusted.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

# Whitelisted canonical paths per platform. Symlinks are resolved before comparison.
_LINUX_WHITELIST: tuple[str, ...] = (
    "/usr/bin/gpg",
    "/usr/bin/gpg2",
    "/usr/local/bin/gpg",
    "/usr/local/bin/gpg2",
    "/bin/gpg",
    "/snap/bin/gpg",
)

_MACOS_WHITELIST: tuple[str, ...] = (
    "/usr/local/bin/gpg",
    "/usr/local/bin/gpg2",
    "/opt/homebrew/bin/gpg",
    "/opt/homebrew/bin/gpg2",
    "/usr/local/MacGPG2/bin/gpg2",
)

_WINDOWS_WHITELIST: tuple[str, ...] = (
    r"C:\Program Files\GnuPG\bin\gpg.exe",
    r"C:\Program Files (x86)\GnuPG\bin\gpg.exe",
    r"C:\Program Files\Git\usr\bin\gpg.exe",
)


def _platform_whitelist() -> tuple[Path, ...]:
    if sys.platform == "win32":
        return tuple(Path(p) for p in _WINDOWS_WHITELIST)
    if sys.platform == "darwin":
        return tuple(Path(p) for p in _MACOS_WHITELIST)
    return tuple(Path(p) for p in _LINUX_WHITELIST)


class DetectionReason(StrEnum):
    NOT_FOUND = "not_found"
    WHITELISTED = "whitelisted"
    USER_OVERRIDE_TRUSTED = "user_override_trusted"
    USER_OVERRIDE_UNTRUSTED = "user_override_untrusted"
    HASH_MISMATCH = "hash_mismatch"
    WORLD_WRITABLE = "world_writable"
    PARENT_WRITABLE = "parent_writable"
    TRUST_PATH_MISMATCH = "trust_path_mismatch"
    IDENTITY_MISMATCH = "identity_mismatch"


class GPGDetectionError(Exception):
    """Raised when GPG cannot be resolved to a usable binary."""

    def __init__(
        self,
        reason: DetectionReason,
        message: str,
        *,
        path: Path | None = None,
        new_sha: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.path = path
        self.new_sha = new_sha


@dataclass(frozen=True)
class DetectedGPG:
    path: Path  # canonical, absolute
    sha256: str
    is_whitelisted: bool
    is_root_owned: bool
    device: int | None = None
    inode: int | None = None


def _is_world_or_group_writable(path: Path) -> bool:
    if sys.platform == "win32":
        return False  # POSIX bit semantics do not apply
    mode = path.stat().st_mode
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonicalise(path: Path) -> Path:
    try:
        return path.resolve(strict=True)
    except (FileNotFoundError, OSError) as exc:
        raise GPGDetectionError(
            DetectionReason.NOT_FOUND, f"cannot resolve {path}: {exc}"
        ) from exc


def _check_writability(path: Path) -> None:
    if _is_world_or_group_writable(path):
        raise GPGDetectionError(
            DetectionReason.WORLD_WRITABLE,
            f"GPG binary {path} is group- or world-writable — refusing to execute",
        )


def _check_parent_writability(path: Path) -> None:
    if sys.platform == "win32":
        return
    current = path.parent
    while True:
        if _is_world_or_group_writable(current):
            raise GPGDetectionError(
                DetectionReason.PARENT_WRITABLE,
                f"GPG parent directory {current} is group- or world-writable",
            )
        if current.parent == current:
            return
        current = current.parent


def _check_root_owned(path: Path) -> bool:
    if sys.platform == "win32":
        return False
    try:
        return path.stat().st_uid == 0
    except OSError:
        return False


def _identity(path: Path) -> tuple[int | None, int | None]:
    if sys.platform == "win32":
        return None, None
    try:
        st = path.stat()
        return st.st_dev, st.st_ino
    except OSError:
        return None, None


def _candidates_from_path() -> list[Path]:
    """Discovered (but not yet trusted) GPG binaries on $PATH, for diagnostics."""
    found: list[Path] = []
    for name in ("gpg2", "gpg") if sys.platform != "win32" else ("gpg.exe", "gpg2.exe"):
        located = shutil.which(name)
        if located:
            found.append(Path(located))
    return found


def detect(
    *,
    user_override_path: str | None = None,
    trusted_hash: str | None = None,
    trusted_path: str | None = None,
    trusted_device: int | None = None,
    trusted_inode: int | None = None,
) -> DetectedGPG:
    """Resolve a trusted GPG binary path.

    Resolution order (planv2.md §9.2):
    1. If `user_override_path` is given, it must either be in the platform
       whitelist OR be pinned by `trusted_hash` (current SHA-256 must match).
    2. Otherwise the first existing whitelist entry whose canonical (symlink-
       resolved) target also appears in the literal whitelist is used.

    The whitelist on the comparison side is treated literally — *not* resolved —
    so that a symlink at a whitelisted name pointing outside the whitelist is
    rejected. (If both ends of the symlink chain happen to be whitelist entries,
    the chain is accepted.)

    Raises `GPGDetectionError` with a `reason` field on every failure mode.
    """
    # Normalise the literal whitelist for set membership tests. We do NOT call
    # .resolve() here — that would canonicalise away the very symlink we want
    # to detect.
    literal_whitelist = {Path(os.path.normpath(p)) for p in _platform_whitelist()}

    if user_override_path:
        override = _canonicalise(Path(user_override_path))
        _check_writability(override)
        _check_parent_writability(override)
        sha = _hash_file(override)
        is_listed = override in literal_whitelist
        device, inode = _identity(override)
        if is_listed:
            return DetectedGPG(
                path=override,
                sha256=sha,
                is_whitelisted=True,
                is_root_owned=_check_root_owned(override),
                device=device,
                inode=inode,
            )
        # Outside the whitelist: require an explicit trust pin that matches.
        if trusted_hash is None:
            raise GPGDetectionError(
                DetectionReason.USER_OVERRIDE_UNTRUSTED,
                f"{override} is not in the standard whitelist and has no trusted hash",
                path=override,
                new_sha=sha,
            )
        if trusted_path is None:
            raise GPGDetectionError(
                DetectionReason.TRUST_PATH_MISMATCH,
                f"{override} has a trusted hash but no trusted path binding",
                path=override,
                new_sha=sha,
            )
        trusted_canonical = _canonicalise(Path(trusted_path))
        if trusted_canonical != override:
            raise GPGDetectionError(
                DetectionReason.TRUST_PATH_MISMATCH,
                f"{override} does not match trusted path {trusted_canonical}",
                path=override,
                new_sha=sha,
            )
        if trusted_hash.lower() != sha.lower():
            raise GPGDetectionError(
                DetectionReason.HASH_MISMATCH,
                f"{override} hash mismatch — refusing to execute",
                path=override,
                new_sha=sha,
            )

        # Verify identity (device/inode) if provided, to detect file substitution.
        if trusted_device is not None and device is not None and device != trusted_device:
            raise GPGDetectionError(
                DetectionReason.IDENTITY_MISMATCH,
                f"{override} device mismatch (trusted={trusted_device}, actual={device})",
                path=override,
                new_sha=sha,
            )
        if trusted_inode is not None and inode is not None and inode != trusted_inode:
            raise GPGDetectionError(
                DetectionReason.IDENTITY_MISMATCH,
                f"{override} inode mismatch (trusted={trusted_inode}, actual={inode})",
                path=override,
                new_sha=sha,
            )

        return DetectedGPG(
            path=override,
            sha256=sha,
            is_whitelisted=False,
            is_root_owned=_check_root_owned(override),
            device=device,
            inode=inode,
        )

    for entry in _platform_whitelist():
        if not entry.exists():
            continue
        canonical = _canonicalise(entry)
        if canonical not in literal_whitelist:
            # Symlink points outside the literal whitelist — reject.
            continue
        _check_writability(canonical)
        _check_parent_writability(canonical)
        device, inode = _identity(canonical)
        return DetectedGPG(
            path=canonical,
            sha256=_hash_file(canonical),
            is_whitelisted=True,
            is_root_owned=_check_root_owned(canonical),
            device=device,
            inode=inode,
        )

    raise GPGDetectionError(
        DetectionReason.NOT_FOUND,
        "no GPG binary found in the platform whitelist",
    )


def diagnostics() -> dict[str, object]:
    """Return information useful for the GPG setup dialog (planv2.md §9.2)."""
    return {
        "platform": sys.platform,
        "whitelist": [str(p) for p in _platform_whitelist()],
        "whitelist_present": [str(p) for p in _platform_whitelist() if p.exists()],
        "path_candidates": [str(p) for p in _candidates_from_path()],
        "env_gnupghome": os.environ.get("GNUPGHOME", ""),
    }
