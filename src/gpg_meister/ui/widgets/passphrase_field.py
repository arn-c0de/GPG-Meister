"""Passphrase input widget with strength indicator (planv2.md §14.6)."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
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

# Strength → (progress-bar value, label, stylesheet). Module-level so it is not
# rebuilt on every keystroke.
_STRENGTH_DISPLAY: dict[PasswordStrength, tuple[int, str, str]] = {
    PasswordStrength.REJECTED: (1, "Too weak", "color: #cc0000"),
    PasswordStrength.WEAK: (2, "Weak", "color: #dd6600"),
    PasswordStrength.ACCEPTABLE: (3, "Acceptable", "color: #aaaa00"),
    PasswordStrength.STRONG: (4, "Strong", "color: #006600"),
}


class PassphraseField(QWidget):
    """Masked passphrase input with a strength indicator bar.

    Signals
    -------
    passphrase_changed: emitted on every keystroke with the current text.
    """

    passphrase_changed: Signal = Signal()

    # Seconds the passphrase stays visible after pressing "Show" before it is
    # automatically re-masked, limiting shoulder-surfing exposure.
    _REVEAL_TIMEOUT_MS = 10_000

    def __init__(self, parent: QWidget | None = None, *, show_strength: bool = True) -> None:
        super().__init__(parent)
        self._show_strength = show_strength
        self._build_ui()
        self._reveal_timer = QTimer(self)
        self._reveal_timer.setSingleShot(True)
        self._reveal_timer.setInterval(self._REVEAL_TIMEOUT_MS)
        self._reveal_timer.timeout.connect(lambda: self._toggle_btn.setChecked(False))

    def _build_ui(self) -> None:
        # Debounce timer: delay strength assessment by 300 ms so assess() is not
        # called (and the full passphrase string is not passed) on every keystroke.
        if self._show_strength:
            self._strength_timer = QTimer(self)
            self._strength_timer.setSingleShot(True)
            self._strength_timer.setInterval(300)
            self._strength_timer.timeout.connect(self._run_strength_assessment)

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
            self._strength_label.hide()
            layout.addWidget(self._strength_label)

    def _toggle_visibility(self, checked: bool) -> None:
        if checked:
            self._field.setEchoMode(QLineEdit.EchoMode.Normal)
            self._toggle_btn.setText("Hide")
            # Auto-revert to masked so a revealed passphrase is not left on screen.
            self._reveal_timer.start()
        else:
            self._field.setEchoMode(QLineEdit.EchoMode.Password)
            self._toggle_btn.setText("Show")
            self._reveal_timer.stop()

    def _on_text_changed(self, text: str) -> None:
        self.passphrase_changed.emit()
        if self._show_strength:
            if not text:
                self._strength_timer.stop()
                self._strength_bar.setValue(0)
                self._strength_label.setText("")
            else:
                self._strength_timer.start()

    def _run_strength_assessment(self) -> None:
        self._update_strength(self._field.text())

    def _update_strength(self, text: str) -> None:
        if not text:
            self._strength_bar.setValue(0)
            self._strength_label.hide()
            return

        result = assess(text)
        bar_val, label_text, style = _STRENGTH_DISPLAY.get(result.strength, (0, "", ""))
        self._strength_bar.setValue(bar_val)
        self._strength_label.setText(label_text)
        self._strength_label.setStyleSheet(style)
        self._strength_label.show()

    def text(self) -> str:
        return self._field.text()

    def clear(self) -> None:
        # Best-effort overwrite of the visible buffer before clearing, then
        # re-mask. Qt's QString backing store cannot be truly zeroed (documented
        # SecureBytes limitation), so this only narrows the residency window.
        current = self._field.text()
        if current:
            self._field.setText("•" * len(current))
        self._field.clear()
        self._reveal_timer.stop()
        if self._toggle_btn.isChecked():
            self._toggle_btn.setChecked(False)
        else:
            self._field.setEchoMode(QLineEdit.EchoMode.Password)

    def setPlaceholderText(self, text: str) -> None:
        self._field.setPlaceholderText(text)

