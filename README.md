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

Implemented through Phase 9 packaging prep:

- PySide6 desktop app with tabs for Keys, Messages, Vault, Settings, and Help
- Local GnuPG integration with whitelist-based binary detection and startup checks
- Encrypted vault export/import using Argon2id + ChaCha20-Poly1305/AES-256-GCM
- Structured diagnostic logging, separate audit log, and security-focused test coverage
- German/English i18n sources with release-time `.qm` compilation
- Release tooling for AppImage/Flatpak, PyInstaller, py2app, SBOM generation, and artifact signing

## Packaging

Build scripts live under [`scripts/`](scripts/) and packaging manifests under
[`packaging/`](packaging/).

```sh
python scripts/build_translations.py
./scripts/build_appimage.sh
./scripts/build_flatpak.sh
./scripts/generate_sbom.sh dist
```

Windows and macOS release entry points:

- `packaging/windows/gpg-meister.spec`
- `packaging/macos/setup.py`

The packaged application does not bundle GnuPG itself. End users still need a local
GnuPG installation that passes the startup whitelist/trust checks described in
`planv2.md` §9.2.
