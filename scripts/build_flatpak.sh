#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export UV_CACHE_DIR="${UV_CACHE_DIR:-$ROOT/.uv-cache}"

cd "$ROOT"
python scripts/build_translations.py

if ! command -v flatpak-builder >/dev/null 2>&1; then
  echo "flatpak-builder is required to build the Flatpak bundle." >&2
  exit 1
fi

flatpak-builder \
  --force-clean \
  --user \
  build/flatpak-app \
  packaging/flatpak/io.github.arn-c0de.GPGMeister.yaml
