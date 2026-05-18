#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# ---------- system dependencies ----------
echo "==> Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    gpg \
    python3-pip \
    python3-venv \
    pipx \
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
    echo "==> Installing uv via pipx (no remote shell script)..."
    # pipx handles isolated environment for the tool.
    pipx install uv
    export PATH="$HOME/.local/bin:$PATH"
    if ! command -v uv &>/dev/null; then
        echo "ERROR: uv still not found after pipx install." >&2
        echo "       Try: pipx install uv  then re-run." >&2
        exit 1
    fi
fi

# ---------- Python environment ----------
echo "==> Syncing Python environment..."
uv sync

# ---------- global launcher ----------
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
ln -sf "$(pwd)/.venv/bin/gpgmeister" "$INSTALL_DIR/gpgmeister"
echo "==> Linked gpgmeister -> $INSTALL_DIR/gpgmeister"

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "NOTE: Add ~/.local/bin to your PATH if not already set:"
    echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
fi

echo ""
echo "Done. Run 'gpgmeister' from anywhere or './start.sh' from this folder."
