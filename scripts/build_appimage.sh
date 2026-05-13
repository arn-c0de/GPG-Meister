#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export UV_CACHE_DIR="${UV_CACHE_DIR:-$ROOT/.uv-cache}"

cd "$ROOT"
python scripts/build_translations.py

if ! command -v linuxdeploy >/dev/null 2>&1; then
  echo "linuxdeploy is required to build the AppImage." >&2
  exit 1
fi

.venv/bin/pyinstaller --noconfirm --clean packaging/windows/gpg-meister.spec

APPDIR="$ROOT/build/appimage/AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/scalable/apps"
cp -R dist/gpg-meister/* "$APPDIR/usr/bin/"
cp packaging/linux/io.github.arn-c0de.GPGMeister.desktop "$APPDIR/usr/share/applications/"
cp packaging/linux/io.github.arn-c0de.GPGMeister.svg "$APPDIR/usr/share/icons/hicolor/scalable/apps/"

linuxdeploy \
  --appdir "$APPDIR" \
  --desktop-file packaging/linux/io.github.arn-c0de.GPGMeister.desktop \
  --icon-file packaging/linux/io.github.arn-c0de.GPGMeister.svg \
  --output appimage
