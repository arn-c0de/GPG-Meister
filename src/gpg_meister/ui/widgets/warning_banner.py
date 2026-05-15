"""Prominent, dismissible warning banner for the UI (planv2.md §14.1)."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QWidget

from gpg_meister.ui.clipboard import copy_text
from gpg_meister.ui.errors.user_error import ErrorSeverity

_SEVERITY_STYLES: dict[ErrorSeverity, str] = {
    ErrorSeverity.INFO: (
        "QFrame { background: #d0e8ff; border: 1px solid #6699cc; border-radius: 4px; }"
        " QLabel { color: #12324a; border: none; background: transparent; }"
        " QPushButton { color: #12324a; border: none; background: transparent; }"
        " QPushButton:hover { background: rgba(18, 50, 74, 0.08); }"
    ),
    ErrorSeverity.WARNING: (
        "QFrame { background: #fff3cd; border: 1px solid #c8a000; border-radius: 4px; }"
        " QLabel { color: #5c4400; border: none; background: transparent; }"
        " QPushButton { color: #5c4400; border: none; background: transparent; }"
        " QPushButton:hover { background: rgba(92, 68, 0, 0.10); }"
    ),
    ErrorSeverity.ERROR: (
        "QFrame { background: #ffe0e0; border: 1px solid #cc4444; border-radius: 4px; }"
        " QLabel { color: #6e1b1b; border: none; background: transparent; }"
        " QPushButton { color: #6e1b1b; border: none; background: transparent; }"
        " QPushButton:hover { background: rgba(110, 27, 27, 0.08); }"
    ),
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
    action_clicked: emitted when the optional action button is clicked.
    """

    dismissed: Signal = Signal()
    action_clicked: Signal = Signal()

    def __init__(
        self,
        message: str,
        *,
        severity: ErrorSeverity = ErrorSeverity.WARNING,
        dismissible: bool = True,
        action_text: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._severity = severity
        self._build_ui(message, dismissible, action_text)
        self._apply_style()

    def _build_ui(self, message: str, dismissible: bool, action_text: str | None) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(8)

        icon_label = QLabel(_SEVERITY_ICONS.get(self._severity, ""))
        icon_label.setFixedWidth(16)
        layout.addWidget(icon_label)

        self._message_label = QLabel(message)
        self._message_label.setTextFormat(Qt.TextFormat.PlainText)
        self._message_label.setWordWrap(True)
        self._message_label.setAccessibleName("Warning message")
        layout.addWidget(self._message_label, stretch=1)

        if action_text:
            self._action_btn = QPushButton(action_text)
            self._action_btn.clicked.connect(self.action_clicked.emit)
            layout.addWidget(self._action_btn)

        # Always add a Copy button for easier error reporting
        copy_btn = QPushButton("Copy")
        copy_btn.setFlat(True)
        copy_btn.setToolTip("Copy message to clipboard")
        copy_btn.clicked.connect(lambda: copy_text(self._message_label.text()))
        layout.addWidget(copy_btn)

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
