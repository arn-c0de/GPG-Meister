# Contributing to GPG Meister

Contributions are welcome, especially language and translation work.

GPG Meister currently ships with:

- English (`en`)
- German (`de`)

## Currently Wanted: More Languages

Language expansion is tracked in [issue #1](https://github.com/arn-c0de/GPG-Meister/issues/1). The project is actively looking for contributors who can add and maintain more UI languages. Good first language contributions include:

- Translating the Qt translation source files in `src/gpg_meister/i18n/`
- Reviewing cryptographic and security terminology for accuracy
- Adding or improving glossary terms for non-English users
- Checking that translated UI text still fits in the desktop interface
- Testing language selection on Linux, Windows, and macOS

If you want to add a new language, comment on issue #1 first so the language code and terminology approach can be agreed before implementation.

## Translation Guidelines

- Keep security terms precise and consistent.
- Prefer clear wording over literal translation.
- Do not soften warnings or destructive-action confirmations.
- Preserve product names such as GPG, GnuPG, OpenPGP, and GPG Meister unless the target language has a standard form.
- Update or add a `terms_<language>.md` glossary when a language needs canonical security vocabulary.
- Rebuild translation files with `python scripts/build_translations.py` before submitting.

## Development Contributions

For code changes, use the existing development workflow:

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run mypy
```

Keep changes focused. Security-sensitive code, cryptography, vault handling, GPG process handling, and key deletion flows need extra review and tests.

## Hall of Fame

Contributors who add, maintain, or significantly review language support can be listed here.

| Contributor | Area | Notes |
| --- | --- | --- |
| arn-c0de | Project maintainer | English and German baseline |

To be added, include your preferred name, contribution area, and optional profile link in the pull request.

## Pull Request Checklist

- The change has a clear purpose.
- Tests or manual verification steps are included.
- UI text is in English unless the change is specifically for translations.
- New translation work follows the terminology guidance above.
- No private keys, passphrases, secrets, or personal key material are committed.
