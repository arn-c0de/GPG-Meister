"""Copy-to-clipboard button with configurable auto-clear timer (planv2.md §5.3)."""

from __future__ import annotations

from PySide6.QtCore import QTimer, Signal
from PySide6.QtWidgets import QApplication, QPushButton, QWidget

from gpg_meister.ui.clipboard import set_sensitive_text


class ClipboardButton(QPushButton):
    """A button that copies text to the clipboard and optionally clears it after a delay.

    If `sensitive=True`, emits `sensitive_copy` so the main window can display a
    warning banner. The auto-clear timer is cancelled if the clipboard content
    changes before the timer fires.

    Signals
    -------
    sensitive_copy: emitted when sensitive=True and a copy has occurred.
    clipboard_cleared: emitted when the auto-clear timer fires.
    """

    sensitive_copy: Signal = Signal()
    clipboard_cleared: Signal = Signal()

    def __init__(
        self,
        label: str = "Copy",
        *,
        sensitive: bool = False,
        clear_after_ms: int = 60_000,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(label, parent)
        self._sensitive = sensitive
        self._clear_after_ms = clear_after_ms
        self._copied_text: str | None = None

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._on_timer)

        self.clicked.connect(self._perform_copy)

        self._text_source: str = ""
        self._quit_connected = False

    def set_text_source(self, text: str) -> None:
        """Set the text that will be copied on click."""
        self._text_source = text

    def _perform_copy(self) -> None:
        text = self._text_source
        if not text:
            return

        if not set_sensitive_text(text):
            return
        self._copied_text = text

        # Clear our secret from the clipboard on quit too, so a shutdown before
        # the timer fires does not leave it behind (M3).
        if not self._quit_connected:
            app = QApplication.instance()
            if app is not None:
                app.aboutToQuit.connect(self._clear_if_ours)
                self._quit_connected = True

        if self._clear_after_ms > 0:
            self._timer.start(self._clear_after_ms)

        if self._sensitive:
            self.sensitive_copy.emit()

        self.setText("Copied!")
        QTimer.singleShot(1500, lambda: self.setText("Copy"))

    def _on_timer(self) -> None:
        clipboard = QApplication.clipboard()
        if clipboard is None:
            return
        if clipboard.text() == self._copied_text:
            clipboard.clear()
            self.clipboard_cleared.emit()
        self._copied_text = None

    def _clear_if_ours(self) -> None:
        """Clear the clipboard on shutdown if it still holds our copied secret."""
        clipboard = QApplication.clipboard()
        if clipboard is not None and self._copied_text is not None and clipboard.text() == self._copied_text:
            clipboard.clear()
        self._copied_text = None

    def stop_timer(self) -> None:
        """Cancel a pending auto-clear. Call when the widget is destroyed."""
        self._timer.stop()
