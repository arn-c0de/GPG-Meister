#!/usr/bin/env bash
#
# Launch the GPG-Meister end-to-end smoke test (scripts/smoke_test.py).
#
# The test runs entirely inside a throwaway temp directory with its own
# GNUPGHOME, audit log, metadata DB and vault. It never touches the real
# ~/.gnupg or the app's user-space directories, and asserts a zero diff over
# them before/after. Safe to run on a machine with real keys.
#
# Usage:   ./smoke-test.sh
# Exit:    0 = all steps passed, 1 = a step failed, 2 = no gpg on PATH.
set -euo pipefail

# Resolve the repo root from this script's location, regardless of cwd.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

if ! command -v gpg &>/dev/null; then
    echo "ERROR: no 'gpg' binary on PATH — the smoke test needs GnuPG." >&2
    exit 2
fi

# Prefer uv (the project's package manager); fall back to a plain interpreter
# with src/ on the path so the test runs even without uv installed.
if command -v uv &>/dev/null; then
    exec uv run --frozen python scripts/smoke_test.py "$@"
elif [[ -x ".venv/bin/python" ]]; then
    exec .venv/bin/python scripts/smoke_test.py "$@"
else
    echo "NOTE: 'uv' not found and no .venv — falling back to system python3." >&2
    echo "      If imports fail, run './install.sh' (or 'uv sync') first." >&2
    exec python3 scripts/smoke_test.py "$@"
fi
