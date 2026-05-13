"""Qt internationalisation scaffolding (planv2.md §14.7).

Call install_translator() after QApplication is created, before any widget is shown.
The locale is resolved from AppConfig.locale (auto → OS locale → 'en' fallback).
"""

from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
from importlib.resources import as_file, files

from PySide6.QtCore import QCoreApplication, QLocale, QTranslator

DEFAULT_LOCALE = "en"
AUTO_LOCALE = "auto"
_LOADED_TRANSLATOR: QTranslator | None = None
_RESOURCE_STACK = ExitStack()


@dataclass(frozen=True)
class LanguageOption:
    code: str
    label: str


def available_translation_codes() -> set[str]:
    """Return locale codes for bundled `.qm` translation resources."""
    package_files = files("gpg_meister.i18n")
    codes = {
        resource.name.removesuffix(".qm")
        for resource in package_files.iterdir()
        if resource.is_file() and resource.name.endswith(".qm")
    }
    codes.add(DEFAULT_LOCALE)
    return codes


def available_language_options() -> list[LanguageOption]:
    """Return language choices suitable for the Settings UI.

    Adding a new `<code>.qm` file to this package automatically exposes the
    language here.
    """
    options = [
        LanguageOption(AUTO_LOCALE, "Auto-detect (follow OS)"),
    ]
    options.extend(
        LanguageOption(code, language_label(code))
        for code in sorted(available_translation_codes(), key=language_label)
    )
    return options


def language_label(locale_code: str) -> str:
    if locale_code == DEFAULT_LOCALE:
        return "English"

    locale = QLocale(locale_code)
    native_name = locale.nativeLanguageName().strip()
    english_name = locale.languageToString(locale.language()).strip()

    if native_name and english_name and native_name.lower() != english_name.lower():
        return f"{native_name} ({english_name})"
    return english_name or locale_code


def resolve_locale(locale_setting: str) -> str:
    """Return a two-letter locale code ('en', 'de', …) from the config setting.

    'auto' resolves to the OS locale; falls back to 'en' if the resolved locale
    has no bundled translation.
    """
    if locale_setting != AUTO_LOCALE:
        return locale_setting

    system_locale = QLocale.system().name()
    lang = system_locale.split("_")[0].lower()
    bundled = available_translation_codes()
    return lang if lang in bundled else DEFAULT_LOCALE


def install_translator(locale_code: str) -> bool:
    """Load and install the Qt .qm translation file for `locale_code`.

    Returns True if a translation was loaded, False if English fallback is used
    (no .qm needed — source strings are English).
    """
    global _LOADED_TRANSLATOR

    if _LOADED_TRANSLATOR is not None:
        QCoreApplication.removeTranslator(_LOADED_TRANSLATOR)
        _LOADED_TRANSLATOR = None

    if locale_code == DEFAULT_LOCALE:
        return False

    if locale_code not in available_translation_codes():
        return False

    resource = files("gpg_meister.i18n").joinpath(f"{locale_code}.qm")
    qm_path = _RESOURCE_STACK.enter_context(as_file(resource))
    translator = QTranslator()
    if translator.load(str(qm_path)):
        QCoreApplication.installTranslator(translator)
        _LOADED_TRANSLATOR = translator
        return True

    return False
