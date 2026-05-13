"""Passphrase input widget with strength indicator (planv2.md §14.6)."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.security.password_policy import PasswordStrength, assess


class PassphraseField(QWidget):
    """Masked passphrase input with a strength indicator bar.

    Signals
    -------
    passphrase_changed: emitted on every keystroke with the current text.
    """

    passphrase_changed: Signal = Signal()

    def __init__(self, parent: QWidget | None = None, *, show_strength: bool = True) -> None:
        super().__init__(parent)
        self._show_strength = show_strength
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        input_row = QHBoxLayout()
        input_row.setSpacing(4)

        self._field = QLineEdit()
        self._field.setEchoMode(QLineEdit.EchoMode.Password)
        self._field.setAccessibleName("Passphrase")
        self._field.setPlaceholderText("Enter passphrase…")
        self._field.textChanged.connect(self._on_text_changed)
        input_row.addWidget(self._field)

        self._toggle_btn = QPushButton("Show")
        self._toggle_btn.setCheckable(True)
        self._toggle_btn.setFixedWidth(56)
        self._toggle_btn.setAccessibleName("Show passphrase")
        self._toggle_btn.toggled.connect(self._toggle_visibility)
        input_row.addWidget(self._toggle_btn)

        layout.addLayout(input_row)

        if self._show_strength:
            self._strength_bar = QProgressBar()
            self._strength_bar.setRange(0, 4)
            self._strength_bar.setValue(0)
            self._strength_bar.setTextVisible(False)
            self._strength_bar.setFixedHeight(6)
            self._strength_bar.setAccessibleName("Passphrase strength")
            layout.addWidget(self._strength_bar)

            self._strength_label = QLabel("")
            self._strength_label.setAlignment(Qt.AlignmentFlag.AlignRight)
            layout.addWidget(self._strength_label)

        self._capslock_label = QLabel("")
        self._capslock_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(self._capslock_label)

    def _toggle_visibility(self, checked: bool) -> None:
        if checked:
            self._field.setEchoMode(QLineEdit.EchoMode.Normal)
            self._toggle_btn.setText("Hide")
        else:
            self._field.setEchoMode(QLineEdit.EchoMode.Password)
            self._toggle_btn.setText("Show")

    def _on_text_changed(self, text: str) -> None:
        self.passphrase_changed.emit()
        if self._show_strength:
            self._update_strength(text)

    def _update_strength(self, text: str) -> None:
        if not text:
            self._strength_bar.setValue(0)
            self._strength_label.setText("")
            return

        result = assess(text)
        strength_map: dict[PasswordStrength, tuple[int, str, str]] = {
            PasswordStrength.REJECTED: (1, "Too weak", "color: #cc0000"),
            PasswordStrength.WEAK: (2, "Weak", "color: #dd6600"),
            PasswordStrength.ACCEPTABLE: (3, "Acceptable", "color: #aaaa00"),
            PasswordStrength.STRONG: (4, "Strong", "color: #006600"),
        }
        bar_val, label_text, style = strength_map.get(
            result.strength, (0, "", "")
        )
        self._strength_bar.setValue(bar_val)
        self._strength_label.setText(label_text)
        self._strength_label.setStyleSheet(style)

    def text(self) -> str:
        return self._field.text()

    def clear(self) -> None:
        self._field.clear()

    def setPlaceholderText(self, text: str) -> None:
        self._field.setPlaceholderText(text)

    def _check_capslock(self) -> None:
        try:
            from PySide6.QtGui import QGuiApplication
            modifiers = QGuiApplication.queryKeyboardModifiers()
            from PySide6.QtCore import Qt as QtCore
            caps = bool(modifiers & QtCore.KeyboardModifier.GroupSwitchModifier)
            self._capslock_label.setText("Caps Lock is on" if caps else "")
        except Exception:  # noqa: S110
            pass  # Caps Lock detection is best-effort; never block on failure.
