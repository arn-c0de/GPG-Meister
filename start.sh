#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export UV_LINK_MODE=copy
unset VIRTUAL_ENV
uv run gpg-meister "$@"
