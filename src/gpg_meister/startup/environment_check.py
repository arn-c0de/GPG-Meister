"""Startup environment checks (planv2.md §5.5).

Run run_all_checks() on every launch. Each check either passes silently, raises
EnvironmentCheckError for hard failures (blocks the application), or returns a
Warning object for soft issues (displayed as a banner in the main window).
"""

from __future__ import annotations

import ctypes
import importlib.util
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from gpg_meister.storage.paths import AppPaths
from gpg_meister.storage.permissions import PermissionStatus, is_safe_for_secrets


class CheckSeverity(StrEnum):
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class CheckWarning:
    code: str
    message: str
    severity: CheckSeverity = CheckSeverity.WARNING


class EnvironmentCheckError(Exception):
    """Raised for hard failures that prevent the application from starting."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class CheckResult:
    warnings: list[CheckWarning] = field(default_factory=list)
    gpg_version: str = ""
    mlock_available: bool = False
    swap_encrypted: bool | None = None


_REQUIRED_VERSION = (2, 2, 0)
_WARN_VERSION = (2, 4, 0)

_REQUIRED_PACKAGES = [
    "cryptography",
    "argon2",
    "gnupg",
    "pydantic",
    "msgpack",
    "structlog",
    "psutil",
    "PySide6",
]


def check_gpg_version(gpg_path: Path) -> str:
    """Return GPG version string. Raises EnvironmentCheckError if too old."""
    try:
        result = subprocess.run(  # noqa: S603
            [str(gpg_path), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        raise EnvironmentCheckError(
            "gpg_version_check_failed",
            f"Failed to query GPG version: {exc}",
        ) from exc

    match = re.search(r"GnuPG\)?\s+(\d+\.\d+\.\d+)", result.stdout)
    if not match:
        raise EnvironmentCheckError(
            "gpg_version_parse_failed",
            "Could not parse GnuPG version from output.",
        )

    version_str = match.group(1)
    parts = tuple(int(x) for x in version_str.split("."))

    if parts < _REQUIRED_VERSION:
        req = ".".join(str(x) for x in _REQUIRED_VERSION)
        raise EnvironmentCheckError(
            "gpg_version_too_old",
            f"GnuPG {version_str} is too old. Version {req} or newer is required.",
        )

    return version_str


def check_directories(paths: AppPaths) -> list[CheckWarning]:
    """Ensure required directories exist with correct permissions."""
    warnings: list[CheckWarning] = []
    paths.ensure()

    for dir_path in (paths.config_dir, paths.data_dir, paths.state_dir):
        if not is_safe_for_secrets(dir_path):
            warnings.append(
                CheckWarning(
                    code="dir_permissions",
                    message=f"Directory {dir_path} is readable by others. "
                    "Consider restricting permissions to 0700.",
                )
            )
    return warnings


def check_config_permissions(config_file: Path) -> list[CheckWarning]:
    """Warn or fail on unsafe config file permissions on POSIX."""
    if sys.platform == "win32":
        return []
    if not config_file.exists():
        return []

    from gpg_meister.storage.permissions import report

    rep = report(config_file)
    if rep.status in (
        PermissionStatus.SYMLINK,
        PermissionStatus.WORLD_WRITABLE,
        PermissionStatus.GROUP_WRITABLE,
    ):
        return [
            CheckWarning(
                code="config_unsafe_permissions",
                message=f"Config file {config_file} is unsafe ({rep.status.value}). "
                f"Refusing to trust it; fix ownership/path and run: chmod 600 {config_file}",
                severity=CheckSeverity.ERROR,
            )
        ]
    if rep.status in (PermissionStatus.WORLD_READABLE, PermissionStatus.GROUP_READABLE):
        return [
            CheckWarning(
                code="config_readable_by_others",
                message=f"Config file {config_file} is readable by other users. "
                f"Run: chmod 600 {config_file}",
                severity=CheckSeverity.ERROR,
            )
        ]
    return []


def check_required_packages() -> list[CheckWarning]:
    """Return warnings for any required package that cannot be imported."""
    missing = [pkg for pkg in _REQUIRED_PACKAGES if importlib.util.find_spec(pkg) is None]
    if missing:
        return [
            CheckWarning(
                code="missing_packages",
                message=f"Required packages not found: {', '.join(missing)}. "
                "Re-run: uv sync",
                severity=CheckSeverity.ERROR,
            )
        ]
    return []


def check_mlock() -> bool:
    """Return True if mlock is available on this platform."""
    if sys.platform == "win32":
        return False
    try:
        buf = ctypes.create_string_buffer(64)
        ctypes.cdll.LoadLibrary("libc.so.6").mlock(buf, ctypes.c_size_t(64))
        return True
    except (OSError, AttributeError):
        return False


def check_swap_encryption() -> tuple[bool | None, list[CheckWarning]]:
    """Probe swap encryption status. Returns (encrypted, warnings)."""
    warnings: list[CheckWarning] = []
    encrypted: bool | None = None

    if sys.platform == "linux":
        encrypted, swap_warnings = _check_swap_linux()
        warnings.extend(swap_warnings)
    elif sys.platform == "darwin":
        encrypted, swap_warnings = _check_swap_macos()
        warnings.extend(swap_warnings)
    elif sys.platform == "win32":
        warnings.append(
            CheckWarning(
                code="swap_not_verified",
                message="Windows page-file contents are not encrypted unless BitLocker "
                "protects the system volume.",
            )
        )

    return encrypted, warnings


def _check_swap_linux() -> tuple[bool | None, list[CheckWarning]]:
    try:
        with open("/proc/swaps", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return None, []

    swap_devices = [line.split()[0] for line in lines[1:] if line.strip()]
    if not swap_devices:
        return True, []

    unencrypted: list[str] = []
    for device in swap_devices:
        if not Path(device).is_block_device():
            continue
        if not device.startswith("/dev/mapper/"):
            unencrypted.append(device)

    if unencrypted:
        return False, [
            CheckWarning(
                code="swap_not_encrypted",
                message="Swap partition(s) appear unencrypted: "
                + ", ".join(unencrypted)
                + ". Private key material may be paged to disk. "
                "Consider using an encrypted swap or disabling swap.",
            )
        ]
    return True, []


def _check_swap_macos() -> tuple[bool | None, list[CheckWarning]]:
    fdesetup = shutil.which("fdesetup")
    if not fdesetup:
        return None, []
    try:
        result = subprocess.run(  # noqa: S603
            [fdesetup, "status"], capture_output=True, text=True, timeout=5
        )
        if "FileVault is On" in result.stdout:
            return True, []
        return False, [
            CheckWarning(
                code="filevault_off",
                message="FileVault is not enabled. The swap partition is not encrypted.",
            )
        ]
    except (subprocess.TimeoutExpired, OSError):
        return None, []


def run_all_checks(
    paths: AppPaths,
    gpg_path: Path,
) -> CheckResult:
    """Run all startup checks. Raises EnvironmentCheckError on hard failures.

    Soft issues are collected into the returned CheckResult.warnings list.
    """
    result = CheckResult()

    # Hard: GPG version
    result.gpg_version = check_gpg_version(gpg_path)

    version_parts = tuple(int(x) for x in result.gpg_version.split("."))
    if version_parts < _WARN_VERSION:
        warn_str = ".".join(str(x) for x in _WARN_VERSION)
        result.warnings.append(
            CheckWarning(
                code="gpg_version_old",
                message=f"GnuPG {result.gpg_version} is below {warn_str}. "
                "Kyber/PQC subkey support and several stability fixes require a newer version.",
            )
        )

    # Directories
    result.warnings.extend(check_directories(paths))

    # Config file permissions
    result.warnings.extend(check_config_permissions(paths.config_file))

    # Packages
    result.warnings.extend(check_required_packages())

    # mlock
    result.mlock_available = check_mlock()

    # Swap
    result.swap_encrypted, swap_warnings = check_swap_encryption()
    result.warnings.extend(swap_warnings)

    return result
