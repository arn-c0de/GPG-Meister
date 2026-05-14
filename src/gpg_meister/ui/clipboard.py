"""Central clipboard helper for sensitive copy operations."""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

_copied_text: str | None = None
_timer: QTimer | None = None


def copy_text(text: str, *, clear_after_seconds: int = 60) -> None:
    """Copy text and clear it later if clipboard content is unchanged."""
    global _copied_text, _timer
    if not text:
        return
    clipboard = QApplication.clipboard()
    if clipboard is None:
        return
    clipboard.setText(text)
    _copied_text = text
    if _timer is None:
        _timer = QTimer()
        _timer.setSingleShot(True)
        _timer.timeout.connect(_clear_if_unchanged)
    if clear_after_seconds > 0:
        _timer.start(clear_after_seconds * 1000)
    else:
        _timer.stop()


def _clear_if_unchanged() -> None:
    global _copied_text
    clipboard = QApplication.clipboard()
    if clipboard is not None and clipboard.text() == _copied_text:
        clipboard.clear()
    _copied_text = None
