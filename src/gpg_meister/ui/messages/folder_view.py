"""Folders tab: encrypt or decrypt a whole folder with a key or a passphrase."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.services.folder_service import ENCRYPTED_FOLDER_SUFFIX, FolderDecryptResult
from gpg_meister.ui.messages.folder_viewmodel import FolderViewModel
from gpg_meister.ui.qt_helpers import busy_bar, error_label
from gpg_meister.ui.widgets.passphrase_field import PassphraseField

_FILE_FILTER = f"Encrypted folder (*{ENCRYPTED_FOLDER_SUFFIX} *.gpg);;All files (*)"


def _path_row(placeholder: str) -> tuple[QHBoxLayout, QLineEdit, QPushButton]:
    row = QHBoxLayout()
    edit = QLineEdit()
    edit.setPlaceholderText(placeholder)
    button = QPushButton("Browse…")
    row.addWidget(edit, stretch=1)
    row.addWidget(button)
    return row, edit, button


class FolderView(QWidget):
    def __init__(self, viewmodel: FolderViewModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vm = viewmodel
        self._build_ui()
        self._connect_signals()
        self._on_mode_changed()
        self._vm.load_keys()

    # ------------------------------------------------------------------- layout

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)
        root.addWidget(self._build_encrypt_box())
        root.addWidget(self._build_decrypt_box())

        self._progress = busy_bar()
        root.addWidget(self._progress)
        self._error_label = error_label()
        root.addWidget(self._error_label)
        self._status_label = QLabel()
        self._status_label.setWordWrap(True)
        self._status_label.setStyleSheet("color: #006600;")
        self._status_label.hide()
        root.addWidget(self._status_label)
        root.addStretch()

    def _build_encrypt_box(self) -> QGroupBox:
        box = QGroupBox("Encrypt folder")
        layout = QVBoxLayout(box)

        row, self._enc_folder, self._btn_enc_browse = _path_row("Folder to encrypt…")
        layout.addLayout(row)

        mode_row = QHBoxLayout()
        self._mode_key = QRadioButton("With a recipient key")
        self._mode_pass = QRadioButton("With a passphrase")
        self._mode_key.setChecked(True)
        self._mode_group = QButtonGroup(self)
        self._mode_group.addButton(self._mode_key)
        self._mode_group.addButton(self._mode_pass)
        mode_row.addWidget(self._mode_key)
        mode_row.addWidget(self._mode_pass)
        mode_row.addStretch()
        layout.addLayout(mode_row)

        self._recip_combo = QComboBox()
        self._recip_combo.setPlaceholderText("Select a recipient key…")
        self._verify_check = QCheckBox("I have verified this recipient key")
        layout.addWidget(self._recip_combo)
        layout.addWidget(self._verify_check)

        self._enc_passphrase = PassphraseField()
        self._enc_passphrase.setPlaceholderText("Passphrase for the folder…")
        self._enc_confirm = PassphraseField(show_strength=False)
        self._enc_confirm.setPlaceholderText("Repeat the passphrase…")
        layout.addWidget(self._enc_passphrase)
        layout.addWidget(self._enc_confirm)

        self._btn_encrypt = QPushButton("Encrypt folder…")
        layout.addWidget(self._btn_encrypt)
        return box

    def _build_decrypt_box(self) -> QGroupBox:
        box = QGroupBox("Decrypt folder")
        layout = QVBoxLayout(box)

        row, self._dec_file, self._btn_dec_browse = _path_row(
            f"Encrypted folder file ({ENCRYPTED_FOLDER_SUFFIX})…"
        )
        layout.addLayout(row)

        self._dec_passphrase = PassphraseField(show_strength=False)
        self._dec_passphrase.setPlaceholderText(
            "Folder passphrase, or the private key's passphrase / card PIN…"
        )
        layout.addWidget(self._dec_passphrase)

        self._btn_decrypt = QPushButton("Decrypt to…")
        layout.addWidget(self._btn_decrypt)
        return box

    def _connect_signals(self) -> None:
        self._vm.keys_loaded.connect(self._on_keys_loaded)
        self._vm.loading_changed.connect(self._on_loading)
        self._vm.operation_succeeded.connect(self._on_success)
        self._vm.operation_failed.connect(self._on_error)

        self._btn_enc_browse.clicked.connect(self._browse_folder)
        self._btn_dec_browse.clicked.connect(self._browse_file)
        self._mode_key.toggled.connect(self._on_mode_changed)
        self._btn_encrypt.clicked.connect(self._submit_encrypt)
        self._btn_decrypt.clicked.connect(self._submit_decrypt)

    # ------------------------------------------------------------------ dialogs

    def _browse_folder(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose folder to encrypt")
        if path:
            self._enc_folder.setText(path)

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose encrypted folder", "", _FILE_FILTER)
        if path:
            self._dec_file.setText(path)

    def _ask_save_path(self, folder: Path) -> str:
        suggested = folder.with_name(folder.name + ENCRYPTED_FOLDER_SUFFIX)
        path, _ = QFileDialog.getSaveFileName(
            self, "Save encrypted folder", str(suggested), _FILE_FILTER
        )
        return path

    def _ask_destination(self, source: Path) -> str:
        return QFileDialog.getExistingDirectory(self, "Decrypt into folder", str(source.parent))

    # ------------------------------------------------------------------- events

    def _on_keys_loaded(self, keys: list[KeyInfo]) -> None:
        self._recip_combo.clear()
        for key in keys:
            if not (key.is_revoked or key.is_expired):
                self._recip_combo.addItem(key.display_label, key.fingerprint)

    def _on_mode_changed(self) -> None:
        with_key = self._mode_key.isChecked()
        self._recip_combo.setVisible(with_key)
        self._verify_check.setVisible(with_key)
        self._enc_passphrase.setVisible(not with_key)
        self._enc_confirm.setVisible(not with_key)

    def _on_loading(self, loading: bool) -> None:
        self._progress.setVisible(loading)
        self._btn_encrypt.setEnabled(not loading)
        self._btn_decrypt.setEnabled(not loading)

    def _on_success(self, result: object) -> None:
        self._error_label.hide()
        if isinstance(result, FolderDecryptResult):
            self._status_label.setText(f"Folder decrypted to: {result.folder}")
        elif isinstance(result, Path):
            self._status_label.setText(f"Folder encrypted to: {result}")
        self._status_label.show()

    def _on_error(self, message: str) -> None:
        self._status_label.hide()
        self._error_label.setText(message)
        self._error_label.show()

    # ------------------------------------------------------------------ submits

    def _submit_encrypt(self) -> None:
        text = self._enc_folder.text().strip()
        if not text:
            self._on_error("Choose a folder to encrypt.")
            return
        recipient: str | None = None
        if self._mode_key.isChecked():
            recipient = self._recip_combo.currentData()
            if not recipient:
                self._on_error("Choose a recipient key.")
                return
            if not self._verify_check.isChecked():
                self._on_error("Confirm that you have verified the recipient key.")
                return
        elif self._enc_passphrase.text() != self._enc_confirm.text():
            self._on_error("The passphrases do not match.")
            return

        folder = Path(text)
        target = self._ask_save_path(folder)
        if not target:
            return
        self._vm.encrypt(
            folder,
            Path(target),
            recipient=recipient,
            trust_confirmed=self._verify_check.isChecked(),
            get_passphrase=self._enc_passphrase.text,
        )
        self._enc_passphrase.clear()
        self._enc_confirm.clear()

    def _submit_decrypt(self) -> None:
        text = self._dec_file.text().strip()
        if not text:
            self._on_error("Choose an encrypted folder file.")
            return
        source = Path(text)
        destination = self._ask_destination(source)
        if not destination:
            return
        self._vm.decrypt(source, Path(destination), get_passphrase=self._dec_passphrase.text)
        self._dec_passphrase.clear()
