# GPG Meister

[![Architecture](https://img.shields.io/badge/architecture-MVVM-1f6feb)](#tech)
[![UI](https://img.shields.io/badge/UI-Qt%206-0A7EA4)](#tech)
[![Runtime](https://img.shields.io/badge/runtime-local--first-2ea043)](#security)
[![Crypto](https://img.shields.io/badge/crypto-GnuPG-F0B400)](#tech)

Desktop app for working with GPG keys, encrypted messages, and backups.

GPG Meister is a local-first desktop app built around GnuPG. It helps with everyday tasks like creating and importing keys, encrypting or signing messages, and exporting encrypted backups of key material.

## Current Status

GPG Meister is actively being developed.

You can already use it, but it is still a work in progress and some parts may change significantly between releases. Behavior, UI details, workflows, and internal structure can still evolve as the project matures.

## What it does
- Create, import, and manage GPG keys
- Encrypt, decrypt, sign, and verify messages
- Export and import encrypted key vault backups
- Keep all operations on your own machine
- Support English and German UI

### Downloads
Prebuilt releases for Linux, Windows, and macOS are available here:

[GitHub Releases](https://github.com/arn-c0de/GPG-Meister/releases)

## Getting Started
### Requirements
- GnuPG 2.2+
- Python 3.11+
- `uv` for the recommended development workflow

## Docs
- [Documentation Overview](docs/overview.md)
- [Plan vs Code](docs/plan-vs-code.md)
- [App and Startup Flow](docs/app-startup.md)
- [Service Layer](docs/services.md)
- [Security Policy](SECURITY.md)
- [Storage Layer](docs/storage.md)
- [UI Layer](docs/ui.md)

## Security
- Local-first design with no cloud dependency
- Encrypted vaults for key backup and transfer
- Dedicated audit logging for security-relevant events
- Safer GnuPG binary detection and trust pinning
- Local metadata store that does not keep private keys or passphrases
- Security reporting policy: [SECURITY.md](SECURITY.md)

## Tech
- Python 3.11+
- PySide6 / Qt 6
- GnuPG
- `python-gnupg`
- Pydantic v2

## Development
```bash
git clone https://github.com/arn-c0de/GPG-Meister.git
cd GPG-Meister
uv sync --extra dev
uv run gpg-meister
```

### Checks
```bash
uv run pytest
uv run ruff check .
uv run mypy
```

## Packaging
```bash
python scripts/build_translations.py
./scripts/build_appimage.sh
./scripts/generate_sbom.sh dist
```

## Contact
- GitHub Issues: [arn-c0de/GPG-Meister/issues](https://github.com/arn-c0de/GPG-Meister/issues)
- GitHub Contact Page: [arn-c0de contact](https://github.com/arn-c0de)
- Email: [arn-c0de@protonmail.com](mailto:arn-c0de@protonmail.com)

If you find bugs, unexpected behavior, or rough edges, please open an issue or get in touch through the GitHub contact options on the user profile.

Contributions, feedback, and collaboration are welcome.

## License
MIT. See the `LICENSE` file.
