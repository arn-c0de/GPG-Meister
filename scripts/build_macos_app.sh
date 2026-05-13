#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export UV_CACHE_DIR="${UV_CACHE_DIR:-$ROOT/.uv-cache}"

cd "$ROOT"
python scripts/build_translations.py
.venv/bin/python packaging/macos/setup.py py2app
