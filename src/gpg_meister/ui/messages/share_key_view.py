"""Share Key tab — export an armored public key to share with others."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.services.key_service import KeyService


class ShareKeyView(QWidget):
    """Share Key tab: select a key and copy/save its armored public key."""

    def __init__(self, key_service: KeyService, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._svc = key_service
        self._keys: list[KeyInfo] = []
        self._build_ui()
        self._load_keys()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        intro = QLabel(
            "Select a key to display its public key in armored text format. "
            "Share this with anyone who wants to send you an encrypted message."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #666666;")
        root.addWidget(intro)

        root.addWidget(QLabel("Key:"))
        key_row = QHBoxLayout()
        self._key_combo = QComboBox()
        self._key_combo.setPlaceholderText("Select a key…")
        self._key_combo.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        key_row.addWidget(self._key_combo, stretch=1)
        root.addLayout(key_row)

        root.addWidget(QLabel("Armored public key (share this with others):"))
        self._armor_output = QTextEdit()
        self._armor_output.setReadOnly(True)
        self._armor_output.setFont(_monospace_font())
        self._armor_output.setPlaceholderText("Select a key above to show its public key…")
        root.addWidget(self._armor_output, stretch=1)

        self._error_label = QLabel()
        self._error_label.setStyleSheet("color: #cc0000;")
        self._error_label.setWordWrap(True)
        self._error_label.hide()
        root.addWidget(self._error_label)

        btn_row = QHBoxLayout()
        self._btn_copy = QPushButton("Copy to Clipboard")
        self._btn_copy.setEnabled(False)
        self._btn_save = QPushButton("Save to File…")
        self._btn_save.setEnabled(False)
        btn_row.addWidget(self._btn_copy)
        btn_row.addWidget(self._btn_save)
        btn_row.addStretch()
        root.addLayout(btn_row)

        self._key_combo.currentIndexChanged.connect(self._on_key_selected)
        self._btn_copy.clicked.connect(self._copy_to_clipboard)
        self._btn_save.clicked.connect(self._save_to_file)

    def load_keys(self) -> None:
        """Reload the key list and reset the view."""
        self._armor_output.clear()
        self._btn_copy.setEnabled(False)
        self._btn_save.setEnabled(False)
        self._error_label.hide()
        self._load_keys()

    def _load_keys(self) -> None:
        try:
            self._keys = self._svc.list_keys()
        except Exception as exc:
            self._show_error(str(exc))
            return

        self._key_combo.blockSignals(True)
        self._key_combo.clear()
        for key in self._keys:
            uid = key.user_ids[0] if key.user_ids else key.fingerprint[-16:]
            label = f"{uid}  [{key.fingerprint[-16:]}]"
            if key.has_private_key:
                label += "  ★"
            self._key_combo.addItem(label, key)
        self._key_combo.blockSignals(False)

        if not self._keys:
            self._show_error("No keys found. Create or import a key first.")

    def _on_key_selected(self, idx: int) -> None:
        self._error_label.hide()
        if idx < 0 or idx >= len(self._keys):
            self._armor_output.clear()
            self._btn_copy.setEnabled(False)
            self._btn_save.setEnabled(False)
            return
        key = self._key_combo.itemData(idx)
        if not isinstance(key, KeyInfo):
            return
        try:
            armored = self._svc.export_public(key.fingerprint)
        except Exception as exc:
            self._show_error(str(exc))
            self._armor_output.clear()
            self._btn_copy.setEnabled(False)
            self._btn_save.setEnabled(False)
            return
        self._armor_output.setPlainText(armored)
        self._btn_copy.setEnabled(True)
        self._btn_save.setEnabled(True)

    def _copy_to_clipboard(self) -> None:
        text = self._armor_output.toPlainText()
        cb = QApplication.clipboard()
        if cb and text:
            cb.setText(text)

    def _save_to_file(self) -> None:
        idx = self._key_combo.currentIndex()
        if idx < 0:
            return
        key = self._key_combo.itemData(idx)
        if not isinstance(key, KeyInfo):
            return
        uid_part = (
            key.user_ids[0].split("<")[0].strip().replace(" ", "_")
            if key.user_ids
            else "key"
        )
        default_name = f"{uid_part}_{key.fingerprint[-8:]}_public.asc"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Public Key",
            default_name,
            "ASCII Armored Key (*.asc);;All Files (*)",
        )
        if not path:
            return
        text = self._armor_output.toPlainText()
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            self._show_error(f"Could not save file: {exc}")

    def _show_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.show()


def _monospace_font() -> QFont:
    from PySide6.QtGui import QFontDatabase
    families = QFontDatabase.families()
    for candidate in ("Cascadia Code", "Fira Code", "Consolas", "Courier New", "Monospace"):
        if candidate in families:
            f = QFont(candidate)
            f.setPointSize(9)
            return f
    f = QFont()
    f.setFixedPitch(True)
    f.setPointSize(9)
    return f
