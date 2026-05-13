"""Prominent, dismissible warning banner for the UI (planv2.md §14.1)."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QWidget

from gpg_meister.ui.errors.user_error import ErrorSeverity

_SEVERITY_STYLES: dict[ErrorSeverity, str] = {
    ErrorSeverity.INFO: "background: #d0e8ff; border: 1px solid #6699cc; border-radius: 4px;",
    ErrorSeverity.WARNING: "background: #fff3cd; border: 1px solid #c8a000; border-radius: 4px;",
    ErrorSeverity.ERROR: "background: #ffe0e0; border: 1px solid #cc4444; border-radius: 4px;",
}

_SEVERITY_ICONS: dict[ErrorSeverity, str] = {
    ErrorSeverity.INFO: "(i)",
    ErrorSeverity.WARNING: "⚠",
    ErrorSeverity.ERROR: "✖",
}


class WarningBanner(QFrame):
    """A dismissible banner strip used to surface non-modal warnings and errors.

    Signals
    -------
    dismissed: emitted when the user closes the banner.
    """

    dismissed: Signal = Signal()

    def __init__(
        self,
        message: str,
        *,
        severity: ErrorSeverity = ErrorSeverity.WARNING,
        dismissible: bool = True,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._severity = severity
        self._build_ui(message, dismissible)
        self._apply_style()

    def _build_ui(self, message: str, dismissible: bool) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(8)

        icon_label = QLabel(_SEVERITY_ICONS.get(self._severity, ""))
        icon_label.setFixedWidth(16)
        layout.addWidget(icon_label)

        self._message_label = QLabel(message)
        self._message_label.setWordWrap(True)
        self._message_label.setAccessibleName("Warning message")
        layout.addWidget(self._message_label, stretch=1)

        if dismissible:
            close_btn = QPushButton("✕")
            close_btn.setFixedSize(24, 24)
            close_btn.setFlat(True)
            close_btn.setAccessibleName("Dismiss warning")
            close_btn.clicked.connect(self._dismiss)
            layout.addWidget(close_btn)

    def _apply_style(self) -> None:
        style = _SEVERITY_STYLES.get(self._severity, "")
        self.setStyleSheet(style)

    def set_message(self, message: str) -> None:
        self._message_label.setText(message)
        self.show()

    def _dismiss(self) -> None:
        self.hide()
        self.dismissed.emit()
