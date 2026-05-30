from __future__ import annotations

import atexit
import os
import shutil
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from gpg_meister.services.gpg_service import GPGService, GPGServiceConfig

_exit_status = 0


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Record pytest's exit code for the hard-exit handler below."""
    global _exit_status
    _exit_status = int(exitstatus)


@atexit.register
def _hard_exit() -> None:
    """Terminate before Qt's C++ static destructors run, dodging a crash.

    The UI tests instantiate a ``QApplication``. On a normal exit, libc runs
    Qt's C++ static destructors (``__run_exit_handlers``) *after* the Python
    interpreter is finalized; those destructors call back into shiboken, which
    dereferences the dead interpreter state and segfaults — every test passes,
    then the process dies with SIGSEGV (CI exit code 139). Registered at import,
    this ``atexit`` handler runs last (after pytest has printed its summary and
    other cleanup has run) and ``os._exit``s with the real status, skipping the
    C++ static destructors entirely.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_exit_status)


def _resolve_gpg_binary() -> Path | None:
    located = shutil.which("gpg") or shutil.which("gpg2")
    return Path(located).resolve() if located else None


@pytest.fixture(scope="session")
def gpg_binary() -> Path:
    binary = _resolve_gpg_binary()
    if binary is None:
        pytest.skip("no GnuPG binary available; integration tests skipped")
    return binary


@pytest.fixture
def isolated_gpg(tmp_path: Path, gpg_binary: Path) -> Iterator[GPGService]:
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    service = GPGService(GPGServiceConfig(binary_path=gpg_binary, home_dir=home))
    yield service
    # Best-effort cleanup; the temp dir is removed by pytest itself.
    shutil.rmtree(home, ignore_errors=True)
