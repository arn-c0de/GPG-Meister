"""Factory-reset helpers for clearing all local app-managed state.

The reset is intentionally two-phase:

- The running app only writes a small marker file.
- The next startup performs the actual deletion before long-lived handles such as
  SQLite, logs, or the GPG home are opened.
"""

from __future__ import annotations

import shutil

from gpg_meister.storage.paths import AppPaths

_MARKER_NAME = ".factory-reset-pending"


def marker_path(paths: AppPaths) -> str:
    return str(paths.config_dir / _MARKER_NAME)


def request_factory_reset(paths: AppPaths) -> None:
    """Schedule a factory reset for the next app launch."""
    paths.ensure()
    (paths.config_dir / _MARKER_NAME).write_text("pending\n", encoding="utf-8")


def perform_pending_factory_reset(paths: AppPaths) -> bool:
    """Delete all local app-managed state if a reset marker is present."""
    marker = paths.config_dir / _MARKER_NAME
    if not marker.exists():
        return False

    for directory in (
        paths.state_dir,
        paths.data_dir,
        paths.cache_dir,
        paths.config_dir,
    ):
        if directory.exists():
            shutil.rmtree(directory)

    paths.ensure()
    return True
