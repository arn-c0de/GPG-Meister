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
    "/app/bin/gpg",
    "/app/bin/gpg2",
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
    NOT_ROOT_OWNED = "not_root_owned"


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
        return _detect_user_override(
            Path(user_override_path),
            literal_whitelist,
            trusted_hash=trusted_hash,
            trusted_path=trusted_path,
            trusted_device=trusted_device,
            trusted_inode=trusted_inode,
        )
    return _detect_from_whitelist(literal_whitelist)


def _accept_whitelisted(path: Path, sha: str) -> DetectedGPG:
    """Accept a binary at a whitelisted path; on POSIX it must be root-owned."""
    device, inode = _identity(path)
    is_root_owned = _check_root_owned(path)
    if not is_root_owned and sys.platform != "win32":
        raise GPGDetectionError(
            DetectionReason.NOT_ROOT_OWNED,
            f"{path} is at a whitelisted path but is not owned by root — "
            "this may indicate binary substitution",
            path=path,
            new_sha=sha,
        )
    return DetectedGPG(
        path=path,
        sha256=sha,
        is_whitelisted=True,
        is_root_owned=is_root_owned,
        device=device,
        inode=inode,
    )


def _detect_user_override(
    override_path: Path,
    literal_whitelist: set[Path],
    *,
    trusted_hash: str | None,
    trusted_path: str | None,
    trusted_device: int | None,
    trusted_inode: int | None,
) -> DetectedGPG:
    override = _canonicalise(override_path)
    _check_writability(override)
    _check_parent_writability(override)
    sha = _hash_file(override)

    if override in literal_whitelist:
        return _accept_whitelisted(override, sha)

    # Outside the whitelist: require an explicit trust pin that matches.
    device, inode = _identity(override)
    _verify_trust_pin(
        override,
        sha,
        device=device,
        inode=inode,
        trusted_hash=trusted_hash,
        trusted_path=trusted_path,
        trusted_device=trusted_device,
        trusted_inode=trusted_inode,
    )
    return DetectedGPG(
        path=override,
        sha256=sha,
        is_whitelisted=False,
        is_root_owned=_check_root_owned(override),
        device=device,
        inode=inode,
    )


def _verify_trust_pin(
    override: Path,
    sha: str,
    *,
    device: int | None,
    inode: int | None,
    trusted_hash: str | None,
    trusted_path: str | None,
    trusted_device: int | None,
    trusted_inode: int | None,
) -> None:
    """Validate a non-whitelisted binary against the stored trust pin.

    The pin must bind path, SHA-256 hash, and (when recorded) the file's
    device/inode identity. Raises `GPGDetectionError` on any mismatch.
    """

    def _fail(reason: DetectionReason, message: str) -> GPGDetectionError:
        return GPGDetectionError(reason, message, path=override, new_sha=sha)

    if trusted_hash is None:
        raise _fail(
            DetectionReason.USER_OVERRIDE_UNTRUSTED,
            f"{override} is not in the standard whitelist and has no trusted hash",
        )
    if trusted_path is None:
        raise _fail(
            DetectionReason.TRUST_PATH_MISMATCH,
            f"{override} has a trusted hash but no trusted path binding",
        )
    trusted_canonical = _canonicalise(Path(trusted_path))
    if trusted_canonical != override:
        raise _fail(
            DetectionReason.TRUST_PATH_MISMATCH,
            f"{override} does not match trusted path {trusted_canonical}",
        )
    if trusted_hash.lower() != sha.lower():
        raise _fail(
            DetectionReason.HASH_MISMATCH,
            f"{override} hash mismatch — refusing to execute",
        )
    if trusted_device is not None and device is not None and device != trusted_device:
        raise _fail(
            DetectionReason.IDENTITY_MISMATCH,
            f"{override} device mismatch (trusted={trusted_device}, actual={device})",
        )
    if trusted_inode is not None and inode is not None and inode != trusted_inode:
        raise _fail(
            DetectionReason.IDENTITY_MISMATCH,
            f"{override} inode mismatch (trusted={trusted_inode}, actual={inode})",
        )


def _detect_from_whitelist(literal_whitelist: set[Path]) -> DetectedGPG:
    for entry in _platform_whitelist():
        if not entry.exists():
            continue
        canonical = _canonicalise(entry)
        if canonical not in literal_whitelist:
            # Symlink points outside the literal whitelist — reject.
            continue
        _check_writability(canonical)
        _check_parent_writability(canonical)
        return _accept_whitelisted(canonical, _hash_file(canonical))

    raise GPGDetectionError(
        DetectionReason.NOT_FOUND,
        "no GPG binary found in the platform whitelist",
    )


def diagnostics() -> dict[str, object]:
    """Return information useful for the GPG setup dialog (planv2.md §9.2).

    Intended for a support bundle, so it deliberately avoids leaking the raw
    GNUPGHOME path (which embeds the username/home layout) — only whether it is
    set is reported.
    """
    return {
        "platform": sys.platform,
        "whitelist": [str(p) for p in _platform_whitelist()],
        "whitelist_present": [str(p) for p in _platform_whitelist() if p.exists()],
        "path_candidates": [str(p) for p in _candidates_from_path()],
        "env_gnupghome_set": bool(os.environ.get("GNUPGHOME")),
    }
