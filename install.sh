#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# ---------- system dependencies ----------
echo "==> Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    gpg \
    libxcb-cursor0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-randr0 \
    libxcb-render-util0 \
    libxcb-shape0 \
    libxcb-xinerama0 \
    libxcb-xkb1 \
    libxkbcommon-x11-0

# ---------- uv ----------
if ! command -v uv &>/dev/null; then
    echo "==> Installing uv via pip (no remote shell script)..."
    # pip verifies PyPI package hashes; no piped-shell attack surface.
    python3 -m pip install --user --quiet uv
    export PATH="$HOME/.local/bin:$PATH"
    if ! command -v uv &>/dev/null; then
        echo "ERROR: uv still not found after pip install." >&2
        echo "       Try: python3 -m pip install --user uv  then re-run." >&2
        exit 1
    fi
fi

# ---------- Python environment ----------
echo "==> Syncing Python environment..."
uv sync

echo ""
echo "Done. Run ./start.sh to launch GPG Meister."
