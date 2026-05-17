"""Monospace, copyable fingerprint label (planv2.md §14.2)."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QWidget

from gpg_meister.ui.clipboard import set_sensitive_text


def _format_fingerprint(fp: str) -> str:
    """Format a 40-char fingerprint as groups of 4 separated by spaces."""
    clean = fp.replace(" ", "").upper()
    return " ".join(clean[i : i + 4] for i in range(0, len(clean), 4))


class FingerprintLabel(QWidget):
    """Displays a GPG fingerprint in monospace with spaced groups and a copy button."""

    def __init__(self, fingerprint: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._raw = fingerprint
        self._build_ui()
        self.set_fingerprint(fingerprint)

    def _build_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._label = QLabel()
        self._label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        self._label.setFont(self._monospace_font())
        self._label.setAccessibleName("Key fingerprint")
        layout.addWidget(self._label, stretch=1)

        self._copy_btn = QPushButton("Copy")
        self._copy_btn.setFixedWidth(52)
        self._copy_btn.setAccessibleName("Copy fingerprint to clipboard")
        self._copy_btn.clicked.connect(self._copy)
        layout.addWidget(self._copy_btn)

    @staticmethod
    def _monospace_font() -> QFont:
        from PySide6.QtGui import QFont, QFontDatabase

        families = QFontDatabase.families()
        for candidate in ("Cascadia Code", "Fira Code", "Consolas", "Courier New", "Monospace"):
            if candidate in families:
                font = QFont(candidate)
                font.setPointSize(10)
                return font
        font = QFont()
        font.setFixedPitch(True)
        font.setPointSize(10)
        return font

    def set_fingerprint(self, fingerprint: str) -> None:
        self._raw = fingerprint
        if fingerprint:
            self._label.setText(_format_fingerprint(fingerprint))
        else:
            self._label.setText("—")

    def fingerprint(self) -> str:
        return self._raw

    def _copy(self) -> None:
        set_sensitive_text(self._raw)
