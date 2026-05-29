#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# ---------- system dependencies ----------
# This installer automates dependencies for Debian/Ubuntu only. On other
# distributions, install the equivalents manually (gpg, python3 venv/pip, pipx,
# and the xcb/xkbcommon libraries Qt needs) and re-run from the "uv" step below.
if ! command -v apt-get &>/dev/null; then
    echo "ERROR: this installer only automates Debian/Ubuntu (apt-get not found)." >&2
    echo "       Install gpg, python3-venv, python3-pip, pipx and the libxcb*/" >&2
    echo "       libxkbcommon-x11 packages with your package manager, then run:" >&2
    echo "         uv sync && ln -sf \"\$(pwd)/.venv/bin/gpgmeister\" ~/.local/bin/gpgmeister" >&2
    exit 1
fi

echo "==> Installing system dependencies (Debian/Ubuntu)..."
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
