from __future__ import annotations

from gpg_meister.i18n import available_language_options, available_translation_codes, resolve_locale


def test_available_translation_codes_includes_release_locales() -> None:
    codes = available_translation_codes()
    assert "de" in codes
    assert "en" in codes


def test_available_language_options_include_bundled_languages() -> None:
    options = {option.code: option.label for option in available_language_options()}
    assert options["auto"] == "Auto-detect (follow OS)"
    assert options["en"] == "English"
    assert "de" in options


def test_resolve_locale_keeps_explicit_locale() -> None:
    assert resolve_locale("pt-BR") == "pt-BR"
