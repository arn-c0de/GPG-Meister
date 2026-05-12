from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from gpg_meister.services.gpg_service import GPGService, GPGServiceConfig


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
