# Contributing to GPG Meister

Contributions are welcome. Please follow the project [Code of Conduct](CODE_OF_CONDUCT.md) when participating in issues, pull requests, translation work, documentation, or other project communication.

## Languages

GPG Meister currently ships with English (`en`) and German (`de`). Additional languages are tracked in [issue #1](https://github.com/arn-c0de/GPG-Meister/issues/1).

Languages are discovered from bundled Qt `.qm` files in `src/gpg_meister/i18n/`. To add a language, provide a translated `.ts` file, build the matching `.qm` file with `python scripts/build_translations.py`, and verify that the language appears in Settings.

Keep security terms precise, do not weaken warnings or delete confirmations, and add a `terms_<language>.md` glossary when needed.

## UI and Design

Small voluntary UI/UX improvements are tracked in [issue #2](https://github.com/arn-c0de/GPG-Meister/issues/2).

Useful contributions include cleaner spacing, better layout behavior, clearer feedback, accessibility improvements, and a more consistent visual hierarchy. Larger redesign ideas should be discussed in issue #2 first.

## Development

Use the existing development workflow:

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run mypy
```

Keep changes focused. Security-sensitive code, cryptography, vault handling, GPG process handling, and key deletion flows require extra review and focused tests.

## Hall of Fame

Contributors who add, maintain, or significantly review language support or UI improvements are listed here.

<table>
  <tr>
    <th>Contributor</th>
    <th>Area</th>
    <th>Notes</th>
  </tr>
  <tr>
    <td>
      <a href="https://github.com/arn-c0de">
        <img src="https://github.com/arn-c0de.png?size=64" width="48" height="48" alt="arn-c0de avatar"><br>
        arn-c0de
      </a>
    </td>
    <td>Project maintainer</td>
    <td>English and German baseline</td>
  </tr>
</table>

To be added, include your preferred name, contribution area, optional profile link, and optional avatar URL in the pull request.

## Pull Request Checklist

- The change has a clear purpose.
- Tests or manual verification steps are included.
- UI text is in English unless the change is specifically for translations.
- Translation work follows the terminology guidance above.
- No private keys, passphrases, secrets, or personal key material are committed.
