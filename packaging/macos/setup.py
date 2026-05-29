from __future__ import annotations

import re
from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).resolve().parents[2]


def _package_version() -> str:
    """Single-source the version from gpg_meister/__init__.py."""
    init = (ROOT / "src" / "gpg_meister" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', init, re.MULTILINE)
    if not match:
        raise RuntimeError("could not find __version__ in gpg_meister/__init__.py")
    return match.group(1)


_VERSION = _package_version()
APP = [str(ROOT / "src" / "gpg_meister" / "app.py")]
DATA_FILES = [
    (
        "i18n",
        [str(path) for path in (ROOT / "src" / "gpg_meister" / "i18n").glob("*.qm")],
    ),
]
OPTIONS = {
    "argv_emulation": False,
    "strip": True,
    "packages": ["gpg_meister"],
    "plist": {
        "CFBundleDisplayName": "GPG Meister",
        "CFBundleName": "GPG Meister",
        "CFBundleIdentifier": "io.github.arn-c0de.GPGMeister",
        "CFBundleShortVersionString": _VERSION,
        "CFBundleVersion": _VERSION,
    },
}


setup(
    name="gpg-meister",
    app=APP,
    data_files=DATA_FILES,
    packages=find_packages(where=str(ROOT / "src")),
    package_dir={"": str(ROOT / "src")},
    options={"py2app": OPTIONS},
)
