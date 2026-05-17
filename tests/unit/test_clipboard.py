from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gpg_meister.ui import clipboard


def test_copy_text_keeps_clear_timer_alive() -> None:
    app = QApplication.instance() or QApplication([])
    before = len(clipboard._ACTIVE_TIMERS)

    clipboard.copy_text("secret", clear_after_seconds=60)

    assert len(clipboard._ACTIVE_TIMERS) == before + 1
    assert app.clipboard().text() == "secret"
    mime = app.clipboard().mimeData()
    assert mime.hasFormat("x-kde-passwordManagerHint")
    assert bytes(mime.data("x-kde-passwordManagerHint")) == b"secret"
    assert mime.hasFormat(
        "application/x-qt-windows-mime;value=\"ExcludeClipboardContentFromMonitorProcessing\""
    )
    assert mime.hasFormat("org.nspasteboard.TransientType")

    timer = clipboard._ACTIVE_TIMERS.pop()
    timer.stop()
    timer.deleteLater()


def test_copy_text_without_auto_clear_does_not_create_timer() -> None:
    QApplication.instance() or QApplication([])
    before = len(clipboard._ACTIVE_TIMERS)

    clipboard.copy_text("public", clear_after_seconds=0)

    assert len(clipboard._ACTIVE_TIMERS) == before
