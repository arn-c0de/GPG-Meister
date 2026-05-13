from __future__ import annotations

from gpg_meister.i18n import available_translation_codes, resolve_locale


def test_available_translation_codes_includes_release_locales() -> None:
    codes = available_translation_codes()
    assert "de" in codes
    assert "en" in codes


def test_resolve_locale_keeps_explicit_locale() -> None:
    assert resolve_locale("de") == "de"
