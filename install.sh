ohen emojis so viel modern #!/usr/bin/env bash
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
    echo "==> Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

# ---------- Python environment ----------
echo "==> Syncing Python environment..."
uv sync

echo ""
echo "Done. Run ./start.sh to launch GPG Meister."
