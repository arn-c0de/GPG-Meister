#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-$ROOT/dist}"
mkdir -p "$OUT_DIR"

cd "$ROOT"
if [ ! -x ".venv/bin/cyclonedx-py" ]; then
  echo "missing .venv/bin/cyclonedx-py; run \`uv sync --extra dev\` first." >&2
  exit 1
fi

.venv/bin/cyclonedx-py environment --output-file "$OUT_DIR/gpg-meister-sbom.json"
