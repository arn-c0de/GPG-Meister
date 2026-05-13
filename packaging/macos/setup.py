from __future__ import annotations

from pathlib import Path

from setuptools import find_packages, setup

ROOT = Path(__file__).resolve().parents[2]
APP = [str(ROOT / "src" / "gpg_meister" / "app.py")]
DATA_FILES = [
    (
        "i18n",
        [str(path) for path in (ROOT / "src" / "gpg_meister" / "i18n").glob("*.qm")],
    ),
]
OPTIONS = {
    "argv_emulation": False,
    "packages": ["gpg_meister"],
    "plist": {
        "CFBundleDisplayName": "GPG Meister",
        "CFBundleName": "GPG Meister",
        "CFBundleIdentifier": "io.github.arn-c0de.GPGMeister",
        "CFBundleShortVersionString": "1.0.2",
        "CFBundleVersion": "1.0.2",
    },
}


setup(
    name="gpg-meister",
    app=APP,
    data_files=DATA_FILES,
    packages=find_packages(where=str(ROOT / "src")),
    package_dir={"": str(ROOT / "src")},
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
