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

try:
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]


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
    core_dumps_disabled: bool = False
    swap_encrypted: bool | None = None


_REQUIRED_VERSION = (2, 2, 0)
_WARN_VERSION = (2, 4, 0)
_MIN_MEMLOCK_BYTES = 16 * 1024 * 1024

_REQUIRED_PACKAGES = [
    "cryptography",
    "argon2",
    "pydantic",
    "msgpack",
    "structlog",
    "PySide6",
]

_PR_SET_DUMPABLE = 4


def disable_core_dumps() -> bool:
    """Disable OS core dumps for this process where the platform exposes controls."""
    ok = True
    if resource is not None:
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (AttributeError, OSError, ValueError):
            ok = False
    if sys.platform.startswith("linux"):
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            ret = libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)
        except (AttributeError, OSError):
            return False
        if ret != 0:
            return False
    return ok


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

    combined = f"{result.stdout}\n{result.stderr}"
    if result.returncode != 0:
        raise EnvironmentCheckError(
            "gpg_version_check_failed",
            f"GPG exited with status {result.returncode}: {combined.strip()[:200]}",
        )

    # Scan both streams: some builds print the banner to stderr.
    match = re.search(r"GnuPG\)?\s+(\d+\.\d+\.\d+)", combined)
    if not match:
        raise EnvironmentCheckError(
            "gpg_version_parse_failed",
            f"Could not parse GnuPG version from output: {combined.strip()[:200]}",
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
    """Return True if mlock succeeds and the OS limit can cover real secrets.

    Uses ctypes.CDLL(None) (the current process's C library) first, which
    works on both glibc and musl libc. Falls back to explicit libc.so.6 for
    older glibc environments where CDLL(None) might not expose mlock.
    """
    if sys.platform == "win32":
        return False
    limit = _memlock_hard_limit()
    if limit is not None and limit < _MIN_MEMLOCK_BYTES:
        return False
    try:
        buf = ctypes.create_string_buffer(64)
        # CDLL(None) loads the current process's libc — works on musl and glibc.
        lib = ctypes.CDLL(None, use_errno=True)
        if not hasattr(lib, "mlock"):
            raise AttributeError
        ret: int = lib.mlock(buf, ctypes.c_size_t(64))
        return ret == 0
    except (OSError, AttributeError):
        pass
    try:
        buf = ctypes.create_string_buffer(64)
        ret = ctypes.cdll.LoadLibrary("libc.so.6").mlock(buf, ctypes.c_size_t(64))
        return ret == 0
    except (OSError, AttributeError):
        return False


def check_memlock_limit() -> list[CheckWarning]:
    if sys.platform == "win32":
        return []
    limit = _memlock_hard_limit()
    if limit is None or limit >= _MIN_MEMLOCK_BYTES:
        return []
    mib = _MIN_MEMLOCK_BYTES // (1024 * 1024)
    return [
        CheckWarning(
            code="memlock_limit_low",
            message="The OS memlock limit is below "
            f"{mib} MiB. Large decrypted messages or vault data may remain pageable "
            "even though small mlock probes can succeed.",
        )
    ]


def _memlock_hard_limit() -> int | None:
    if resource is None:
        return None
    try:
        _soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    except (AttributeError, OSError, ValueError):
        return None
    if hard == resource.RLIM_INFINITY:
        return None
    return int(hard)


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


def _is_dm_crypt_device(
    device: str,
    *,
    sys_block_root: Path = Path("/sys/class/block"),
) -> bool:
    """Return True if `device` or any parent block device is a dm-crypt target."""
    try:
        block_name = Path(device).resolve().name
    except OSError:
        block_name = Path(device).name
    return _block_chain_has_dm_crypt(block_name, sys_block_root=sys_block_root, seen=set())


def _block_chain_has_dm_crypt(
    block_name: str,
    *,
    sys_block_root: Path,
    seen: set[str],
) -> bool:
    if block_name in seen:
        return False
    seen.add(block_name)
    block_path = sys_block_root / block_name
    uuid_path = block_path / "dm" / "uuid"
    try:
        if uuid_path.exists():
            uuid = uuid_path.read_text(encoding="utf-8", errors="replace").strip()
            if uuid.startswith("CRYPT-"):
                return True
    except OSError:
        return False

    slaves_path = block_path / "slaves"
    try:
        slaves = list(slaves_path.iterdir()) if slaves_path.exists() else []
    except OSError:
        return False
    return any(
        _block_chain_has_dm_crypt(slave.name, sys_block_root=sys_block_root, seen=seen)
        for slave in slaves
    )


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
    swap_files: list[str] = []
    for device in swap_devices:
        if not Path(device).is_block_device():
            swap_files.append(device)
            continue
        if _is_dm_crypt_device(device):
            continue  # device-mapper crypto target — treat as encrypted

        # Whitelist zram devices (swap-in-RAM, no disk persistence).
        if device.startswith("/dev/zram") or "/dev/zram" in device:
            continue

        unencrypted.append(device)

    warnings: list[CheckWarning] = []
    if unencrypted:
        warnings.append(
            CheckWarning(
                code="swap_not_encrypted",
                message="Swap partition(s) appear unencrypted: "
                + ", ".join(unencrypted)
                + ". Private key material may be paged to disk. "
                "Consider using an encrypted swap or disabling swap.",
            )
        )
    if swap_files:
        warnings.append(
            CheckWarning(
                code="swap_file_unverified",
                message="Swap file(s) detected: "
                + ", ".join(swap_files)
                + ". Encryption status cannot be verified. "
                "Private key material may be paged to an unencrypted swap file.",
            )
        )
    if warnings:
        return False, warnings
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
    result.core_dumps_disabled = disable_core_dumps()
    if not result.core_dumps_disabled:
        # A strong warning, not a hard block: on seccomp/musl/hardened hosts the
        # prctl call is denied, and refusing to start there would be worse than
        # running with core dumps that the OS may already restrict separately.
        result.warnings.append(
            CheckWarning(
                code="core_dumps_enabled",
                message=(
                    "Core dumps could not be disabled for this process. If this host can "
                    "produce core dumps, a crash could persist decrypted secrets to disk. "
                    "Consider disabling core dumps system-wide (e.g. ulimit -c 0)."
                ),
                severity=CheckSeverity.WARNING,
            )
        )

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
    result.warnings.extend(check_memlock_limit())

    # Swap
    result.swap_encrypted, swap_warnings = check_swap_encryption()
    result.warnings.extend(swap_warnings)

    return result
