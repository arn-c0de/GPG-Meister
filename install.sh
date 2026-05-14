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
    echo "uv is required but was not found."
    echo "Install uv with your OS package manager or a verified pinned release, then re-run this script."
    echo "Project setup intentionally does not execute remote installer scripts."
    exit 1
fi

# ---------- Python environment ----------
echo "==> Syncing Python environment..."
uv sync

echo ""
echo "Done. Run ./start.sh to launch GPG Meister."
