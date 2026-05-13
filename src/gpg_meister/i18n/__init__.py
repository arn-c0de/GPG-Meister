"""Qt internationalisation scaffolding (planv2.md §14.7).

Call install_translator() after QApplication is created, before any widget is shown.
The locale is resolved from AppConfig.locale (auto → OS locale → 'en' fallback).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QCoreApplication, QLocale, QTranslator

_TRANSLATIONS_DIR = Path(__file__).parent

_LOADED_TRANSLATOR: QTranslator | None = None


def resolve_locale(locale_setting: str) -> str:
    """Return a two-letter locale code ('en', 'de', …) from the config setting.

    'auto' resolves to the OS locale; falls back to 'en' if the resolved locale
    has no bundled translation.
    """
    if locale_setting != "auto":
        return locale_setting

    system_locale = QLocale.system().name()
    lang = system_locale.split("_")[0].lower()
    bundled = {p.stem for p in _TRANSLATIONS_DIR.glob("*.qm")}
    return lang if lang in bundled else "en"


def install_translator(locale_code: str) -> bool:
    """Load and install the Qt .qm translation file for `locale_code`.

    Returns True if a translation was loaded, False if English fallback is used
    (no .qm needed — source strings are English).
    """
    global _LOADED_TRANSLATOR

    if _LOADED_TRANSLATOR is not None:
        QCoreApplication.removeTranslator(_LOADED_TRANSLATOR)
        _LOADED_TRANSLATOR = None

    if locale_code == "en":
        return False

    qm_path = _TRANSLATIONS_DIR / f"{locale_code}.qm"
    if not qm_path.exists():
        return False

    translator = QTranslator()
    if translator.load(str(qm_path)):
        QCoreApplication.installTranslator(translator)
        _LOADED_TRANSLATOR = translator
        return True

    return False
