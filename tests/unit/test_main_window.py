from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QWidget

from gpg_meister.models.config import AppPage
from gpg_meister.ui.main_window import MainWindow


def test_main_window_restores_current_page() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.install_vault_tab(QWidget())

    assert window.set_current_page(AppPage.VAULT)
    app.processEvents()

    assert window.current_page() == AppPage.VAULT


def test_main_window_emits_page_changes() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    changes: list[str] = []
    window.current_page_changed.connect(changes.append)

    assert window.set_current_page(AppPage.HELP)
    app.processEvents()

    assert changes[-1] == AppPage.HELP.value
