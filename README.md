# GPG Meister

Local-first desktop application for GPG key management, message encryption/decryption,
and encrypted key vault backup/transfer. Runs entirely on the user's machine — no
server, no telemetry. Private keys never leave the device unencrypted.

See [`planv2.md`](planv2.md) for the architecture and implementation plan.

## Development

```sh
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run mypy
```

## Status

In active development. Phase 1 (cryptographic primitives and core models) is the
current focus. See `planv2.md` §10 for the full roadmap.
