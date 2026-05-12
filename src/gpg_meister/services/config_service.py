"""Load, validate, and persist `AppConfig` as TOML.

Reads from `<paths.config_dir>/config.toml`. Writes atomically via
`storage.atomic_write` to avoid leaving a half-written config on crash. Sensitive
values (passphrases, keys) are not part of `AppConfig` and never appear here.
"""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

import tomli_w
from pydantic import ValidationError

from gpg_meister.models.config import AppConfig
from gpg_meister.services.errors import ServiceError
from gpg_meister.storage.atomic_write import atomic_write_bytes
from gpg_meister.storage.permissions import is_safe_for_secrets


class ConfigServiceError(ServiceError):
    """Raised for malformed config files."""


def load(path: Path) -> AppConfig:
    """Load the config from `path`, returning defaults if the file does not exist.

    Raises `ConfigServiceError` on malformed TOML or schema violations.
    """
    if not path.exists():
        return AppConfig()

    try:
        data = path.read_bytes()
        obj = tomllib.loads(data.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigServiceError(f"could not read {path}: {exc}") from exc

    try:
        return AppConfig.model_validate(obj)
    except ValidationError as exc:
        raise ConfigServiceError(f"invalid config: {exc}") from exc


def save(config: AppConfig, path: Path) -> None:
    """Persist the config atomically with mode 0o600 on POSIX.

    None values are omitted because TOML has no null literal.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    obj = config.model_dump(mode="json", exclude_none=True)
    data = tomli_w.dumps(obj).encode("utf-8")
    atomic_write_bytes(path, data, mode=0o600)


def warn_if_world_readable(path: Path) -> str | None:
    """Return a warning string when the config file is world/group readable on
    POSIX, otherwise None. Used by the startup environment check (§5.5)."""
    if sys.platform == "win32" or not path.exists():
        return None
    if is_safe_for_secrets(path):
        return None
    return (
        f"config file {path} is readable by other users — "
        "set permissions to 600 (read/write by you only)"
    )
