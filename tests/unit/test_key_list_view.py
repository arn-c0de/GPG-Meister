from __future__ import annotations

import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gpg_meister.ui.keys.key_list_view import KeyListView
from gpg_meister.ui.keys.key_list_viewmodel import KeyListViewModel


class _FakeKeyService:
    def list_keys(self) -> list[object]:
        return []


def test_new_key_button_reenabled_after_initial_refresh() -> None:
    app = QApplication.instance() or QApplication([])
    view = KeyListView(KeyListViewModel(_FakeKeyService()))

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        app.processEvents()
        if view._btn_create.isEnabled():
            break
        time.sleep(0.01)

    assert view._btn_create.isEnabled()
