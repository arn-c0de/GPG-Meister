# GPG Meister

Desktop app for working with GPG keys, encrypted messages, and backups.

GPG Meister is a local app built around GnuPG. It helps with common tasks like creating and importing keys, encrypting or signing messages, and exporting protected backups.

## What it does
- Create, import, and manage GPG keys
- Encrypt, decrypt, sign, and verify messages
- Export and import encrypted key backups
- Run fully on your own machine
- Support English and German

## Tech
- Python
- PySide6 / Qt
- GnuPG

## Security
- Local-first: no cloud service required
- Encrypted vaults for key backups
- Log filtering for sensitive data
- Safer GnuPG binary detection

## Getting Started
### Requirements
- GnuPG 2.2+
- Python 3.11+

### Downloads
Prebuilt releases for Linux, Windows, and macOS are available here:

[GitHub Releases](https://github.com/arn-c0de/GPG-Meister/releases)

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
- Email: [arn-c0de@protonmail.com](mailto:arn-c0de@protonmail.com)

## License
LGPL. See the `LICENSE` file.
