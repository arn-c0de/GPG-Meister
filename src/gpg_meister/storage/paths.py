"""XDG-aware path resolution for GPG Meister.

POSIX: follows the XDG Base Directory Specification.
Windows: uses %APPDATA%\\GPGMeister (config + data combined under one root).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

_APP_DIRNAME = "gpg-meister"
_APP_DIRNAME_WINDOWS = "GPGMeister"


def _xdg_or_default(env_var: str, default: Path) -> Path:
    value = os.environ.get(env_var)
    if value:
        candidate = Path(value).expanduser()
        if candidate.is_absolute():
            return candidate
    return default


@dataclass(frozen=True)
class AppPaths:
    """Resolved application directories. All paths are absolute.

    The directories are *resolved* but not yet *created* — call `ensure()` to create
    them with the correct permissions.
    """

    config_dir: Path
    data_dir: Path
    state_dir: Path
    cache_dir: Path

    @property
    def gnupg_home(self) -> Path:
        return self.data_dir / "gnupg"

    @property
    def vault_dir(self) -> Path:
        return self.data_dir / "vaults"

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def metadata_db(self) -> Path:
        return self.data_dir / "metadata.sqlite3"

    @property
    def audit_log(self) -> Path:
        return self.state_dir / "audit.log"

    @property
    def diagnostic_log(self) -> Path:
        return self.state_dir / "diagnostic.log"

    def ensure(self) -> None:
        """Create all directories with mode 0700 on POSIX. Idempotent."""
        for path in (
            self.config_dir,
            self.data_dir,
            self.state_dir,
            self.cache_dir,
            self.gnupg_home,
            self.vault_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)
            if sys.platform != "win32":
                path.chmod(0o700)


def resolve_paths() -> AppPaths:
    """Resolve application paths based on the host platform.

    On POSIX, XDG_* environment overrides are honoured if they point at an absolute
    path. On Windows, %APPDATA% is the root for config + data; logs live alongside.
    """
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        root = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        base = root / _APP_DIRNAME_WINDOWS
        return AppPaths(
            config_dir=base / "config",
            data_dir=base / "data",
            state_dir=base / "logs",
            cache_dir=base / "cache",
        )

    home = Path.home()
    config_home = _xdg_or_default("XDG_CONFIG_HOME", home / ".config")
    data_home = _xdg_or_default("XDG_DATA_HOME", home / ".local" / "share")
    state_home = _xdg_or_default("XDG_STATE_HOME", home / ".local" / "state")
    cache_home = _xdg_or_default("XDG_CACHE_HOME", home / ".cache")

    return AppPaths(
        config_dir=config_home / _APP_DIRNAME,
        data_dir=data_home / _APP_DIRNAME,
        state_dir=state_home / _APP_DIRNAME,
        cache_dir=cache_home / _APP_DIRNAME,
    )
