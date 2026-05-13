from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pathlib import Path

from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox

from gpg_meister.app import _apply_appearance
from gpg_meister.models.config import AppConfig, AppearanceMode
from gpg_meister.services.config_service import load
from gpg_meister.storage.paths import AppPaths
from gpg_meister.ui.settings.settings_view import SettingsView
from gpg_meister.ui.settings.settings_viewmodel import SettingsViewModel


def _paths(root: Path) -> AppPaths:
    return AppPaths(
        config_dir=root / "config",
        data_dir=root / "data",
        state_dir=root / "state",
        cache_dir=root / "cache",
    )


def test_factory_reset_requires_second_confirmation(tmp_path: Path, monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    view = SettingsView(SettingsViewModel(AppConfig(), _paths(tmp_path)))
    scheduled: list[bool] = []
    view._vm.factory_reset_scheduled.connect(lambda: scheduled.append(True))

    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        lambda *args, **kwargs: ("nope", True),
    )

    view._confirm_factory_reset()
    app.processEvents()

    assert scheduled == []


def test_day_mode_selection_is_saved(tmp_path: Path) -> None:
    app = QApplication.instance() or QApplication([])
    paths = _paths(tmp_path)
    view = SettingsView(SettingsViewModel(AppConfig(), paths))

    idx = view._appearance_combo.findData(AppearanceMode.LIGHT.value)
    assert idx >= 0
    view._appearance_combo.setCurrentIndex(idx)
    view._vm.save()
    app.processEvents()

    assert load(paths.config_file).appearance == AppearanceMode.LIGHT


def test_day_mode_keeps_widget_style_and_font() -> None:
    app = QApplication.instance() or QApplication([])
    style_before = app.style().objectName()
    font_before = app.font().toString()
    stylesheet_before = app.styleSheet()

    _apply_appearance(app, AppConfig(appearance=AppearanceMode.LIGHT))

    assert app.style().objectName() == style_before
    assert app.font().toString() == font_before
    assert app.styleSheet() == stylesheet_before

    _apply_appearance(app, AppConfig())


def test_factory_reset_schedules_when_second_confirmation_matches(
    tmp_path: Path,
    monkeypatch,
) -> None:
    app = QApplication.instance() or QApplication([])
    paths = _paths(tmp_path)
    view = SettingsView(SettingsViewModel(AppConfig(), paths))
    scheduled: list[bool] = []
    view._vm.factory_reset_scheduled.connect(lambda: scheduled.append(True))

    monkeypatch.setattr(
        QMessageBox,
        "warning",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        lambda *args, **kwargs: ("RESET", True),
    )

    view._confirm_factory_reset()
    app.processEvents()

    assert scheduled == [True]
    assert (paths.config_dir / ".factory-reset-pending").exists()
