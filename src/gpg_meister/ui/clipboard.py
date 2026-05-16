"""Central clipboard helper for sensitive copy operations."""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

_ACTIVE_TIMERS: list[QTimer] = []


def copy_text(text: str, *, clear_after_seconds: int = 60) -> None:
    """Copy text and schedule an independent per-copy clear timer."""
    if not text:
        return
    clipboard = QApplication.clipboard()
    if clipboard is None:
        return
    clipboard.setText(text)
    if clear_after_seconds <= 0:
        return
    snapshot = text
    timer = QTimer()
    timer.setSingleShot(True)
    _ACTIVE_TIMERS.append(timer)

    def _clear() -> None:
        try:
            cb = QApplication.clipboard()
            if cb is not None and cb.text() == snapshot:
                cb.clear()
        finally:
            if timer in _ACTIVE_TIMERS:
                _ACTIVE_TIMERS.remove(timer)
            timer.deleteLater()

    timer.timeout.connect(_clear)
    timer.start(clear_after_seconds * 1000)
