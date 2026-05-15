#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export UV_LINK_MODE=copy
uv run gpg-meister "$@"
