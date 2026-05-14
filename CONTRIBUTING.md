# Contributing to GPG Meister

Contributions are welcome. Please follow the project [Code of Conduct](CODE_OF_CONDUCT.md) when participating in issues, pull requests, translation work, or other project communication.

## Languages

GPG Meister currently ships with English (`en`) and German (`de`). More languages are tracked in [issue #1](https://github.com/arn-c0de/GPG-Meister/issues/1).

Languages are discovered from bundled Qt `.qm` files in `src/gpg_meister/i18n/`. To add one, add a translated `.ts` file, build the matching `.qm` with `python scripts/build_translations.py`, and verify that it appears in Settings.

Keep security terms precise, do not weaken warnings or delete confirmations, and add a `terms_<language>.md` glossary when needed.

## UI and Design

Small voluntary UI/UX improvements are tracked in [issue #2](https://github.com/arn-c0de/GPG-Meister/issues/2).

Useful contributions include cleaner spacing, better layout behavior, clearer feedback, accessibility improvements, and more consistent visual hierarchy. Larger redesign ideas should be discussed in issue #2 first.

## Development

Use the existing development workflow:

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run mypy
```

Keep changes focused. Security-sensitive code, cryptography, vault handling, GPG process handling, and key deletion flows need extra review and tests.

## Hall of Fame

Contributors who add, maintain, or significantly review language support or UI improvements are listed here.

| Contributor | Area | Notes |
| :--- | :--- | :--- |
| **arn-c0de** | Project maintainer | English and German baseline |

To be added, include your preferred name, contribution area, and an optional link to your profile in your pull request.

## Pull Request Checklist

- The change has a clear purpose.
- Tests or manual verification steps are included.
- UI text is in English unless the change is specifically for translations.
- Translation work follows the terminology guidance above.
- No private keys, passphrases, secrets, or personal key material are committed.
