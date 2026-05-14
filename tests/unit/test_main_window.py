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


def test_show_backup_reminder_adds_banner_and_switches_tab() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    window.install_vault_tab(QWidget())
    window.show() # Make window visible
    app.processEvents()

    # Ensure we are NOT on the vault tab initially
    window.set_current_page(AppPage.KEYS)
    app.processEvents()
    assert window.current_page() == AppPage.KEYS

    window.show_backup_reminder("test_uid")
    app.processEvents()

    # Find the banner
    banner = None
    for b in window._banners:
        if "test_uid" in b._message_label.text():
            banner = b
            break

    assert banner is not None
    assert banner.isVisible()

    # Simulate clicking the action button
    banner.action_clicked.emit()
    app.processEvents()

    assert window.current_page() == AppPage.VAULT
