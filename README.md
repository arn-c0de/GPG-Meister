# GPG Meister

<p align="center">
  <img src="logo.png" alt="GPG Meister Logo" width="140">
</p>

[![Architecture](https://img.shields.io/badge/architecture-MVVM-1f6feb)](#tech)
[![UI](https://img.shields.io/badge/UI-Qt%206-0A7EA4)](#tech)
[![Runtime](https://img.shields.io/badge/runtime-local--first-2ea043)](#security)
[![Crypto](https://img.shields.io/badge/crypto-GnuPG-F0B400)](#tech)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/arn-c0de/GPG-Meister)

Desktop app for working with GPG keys, encrypted messages, and backups.

GPG Meister is a local-first desktop app built around GnuPG. It helps with everyday tasks like creating and importing keys, encrypting or signing messages, and exporting encrypted backups of key material.

## Contributing

Language contributors are currently wanted. GPG Meister supports English and German today, and more UI languages are tracked in [issue #1](https://github.com/arn-c0de/GPG-Meister/issues/1).

See [CONTRIBUTING.md](CONTRIBUTING.md) for translation guidelines, development notes, and the contributor Hall of Fame.

## Current Status

> [!WARNING]
> GPG Meister is in active development.
>
> **Important:** While functional, internal structures and the vault format may change significantly between releases. Always ensure you have independent backups of your GPG keys before updating the application. Behavior, UI details, and workflows are still evolving.

## What it does
- **Key Management**: Create, import, and manage GPG keys.
  <img src="images/GPG-MEISTER-keys-page.png" alt="Key Management" width="600">
- **Message Operations**: Encrypt, decrypt, sign, and verify messages.
  <img src="images/GPG-MEISTER-encrypt-page.png" alt="Encryption" width="600">
  <img src="images/GPG-MEISTER-decrypt-page.png" alt="Decryption" width="600">
- **Secure Backups**: Export and import encrypted key vault backups.
  <img src="images/GPG-MEISTER-vault.png" alt="Vault Management" width="600">
- **Help System**: Built-in help and glossary.
  <img src="images/GPG-MEISTER-help-page.png" alt="Help Page" width="600">
- **Local-First**: Keep all operations on your own machine.
- **Internationalization**: Support English and German UI.

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
- [Code of Conduct](CODE_OF_CONDUCT.md)
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
uv run gpgmeister
```

### Run `gpgmeister` from anywhere

`install.sh` links `gpgmeister` into `~/.local/bin` automatically, so after
installation the command is available system-wide:

```bash
gpgmeister
```

Make sure `~/.local/bin` is in your `PATH` (it usually is by default on Linux).
If not, add it once:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
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
