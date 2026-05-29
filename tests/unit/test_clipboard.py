from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gpg_meister.ui import clipboard


def _drain_pending() -> None:
    while clipboard._PENDING:
        entry = clipboard._PENDING.pop()
        entry.timer.stop()
        entry.timer.deleteLater()


def test_copy_text_keeps_clear_timer_alive() -> None:
    app = QApplication.instance() or QApplication([])
    _drain_pending()

    clipboard.copy_text("secret", clear_after_seconds=60)

    assert len(clipboard._PENDING) == 1
    assert app.clipboard().text() == "secret"
    mime = app.clipboard().mimeData()
    assert mime.hasFormat("x-kde-passwordManagerHint")
    assert bytes(mime.data("x-kde-passwordManagerHint")) == b"secret"
    assert mime.hasFormat(
        "application/x-qt-windows-mime;value=\"ExcludeClipboardContentFromMonitorProcessing\""
    )
    assert mime.hasFormat("org.nspasteboard.TransientType")

    _drain_pending()


def test_copy_text_without_auto_clear_does_not_create_timer() -> None:
    QApplication.instance() or QApplication([])
    _drain_pending()

    clipboard.copy_text("public", clear_after_seconds=0)

    assert len(clipboard._PENDING) == 0


def test_flush_pending_clears_wipes_clipboard_on_quit() -> None:
    app = QApplication.instance() or QApplication([])
    _drain_pending()

    clipboard.copy_text("top-secret", clear_after_seconds=60)
    assert app.clipboard().text() == "top-secret"
    assert len(clipboard._PENDING) == 1

    clipboard.flush_pending_clears()

    # Our secret is gone and no pending timers remain.
    assert app.clipboard().text() == ""
    assert len(clipboard._PENDING) == 0


def test_flush_does_not_wipe_unrelated_clipboard_content() -> None:
    app = QApplication.instance() or QApplication([])
    _drain_pending()

    clipboard.copy_text("our-secret", clear_after_seconds=60)
    # The user copies something else afterwards.
    app.clipboard().setText("user-typed-this")

    clipboard.flush_pending_clears()

    # We only wipe our own snapshot, never the user's later content.
    assert app.clipboard().text() == "user-typed-this"


def test_default_clear_seconds_is_used_when_unspecified() -> None:
    QApplication.instance() or QApplication([])
    _drain_pending()
    try:
        clipboard.set_default_clear_seconds(0)
        clipboard.copy_text("secret")  # no explicit clear_after_seconds
        # With a 0 default the auto-clear is disabled → no pending timer.
        assert len(clipboard._PENDING) == 0
    finally:
        clipboard.set_default_clear_seconds(60)
        _drain_pending()
