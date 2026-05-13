"""Vault export view (planv2.md §4.8, §14.3)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.services.vault_service import VaultDescriptor
from gpg_meister.ui.vault.vault_export_viewmodel import VaultExportViewModel
from gpg_meister.ui.widgets.passphrase_field import PassphraseField


class VaultExportView(QWidget):
    """Export tab: select keys, choose file, set passphrases, create vault."""

    def __init__(
        self, viewmodel: VaultExportViewModel, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._vm = viewmodel
        self._build_ui()
        self._connect_signals()
        self._vm.load_keys()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Key selection
        key_box = QGroupBox("Keys to include in vault")
        key_layout = QVBoxLayout(key_box)
        key_layout.addWidget(QLabel("Select private keys to back up (only keys with private key available are listed):"))
        self._key_list = QListWidget()
        self._key_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        key_layout.addWidget(self._key_list)
        layout.addWidget(key_box)

        # Target path
        path_box = QGroupBox("Output file")
        path_layout = QHBoxLayout(path_box)
        self._path_field = QLineEdit()
        self._path_field.setPlaceholderText("Choose vault file path…")
        self._path_field.setReadOnly(True)
        self._btn_browse = QPushButton("Browse…")
        path_layout.addWidget(self._path_field, stretch=1)
        path_layout.addWidget(self._btn_browse)
        layout.addWidget(path_box)

        # Description
        desc_box = QGroupBox("Description (optional)")
        desc_layout = QVBoxLayout(desc_box)
        self._desc_field = QLineEdit()
        self._desc_field.setPlaceholderText("e.g. Home workstation backup 2026-05-13")
        desc_layout.addWidget(self._desc_field)
        layout.addWidget(desc_box)

        # Passphrases
        pp_box = QGroupBox("Passphrases")
        pp_layout = QVBoxLayout(pp_box)
        pp_layout.addWidget(QLabel("Vault master passphrase:"))
        self._master_pp = PassphraseField(show_strength=True)
        self._master_pp.setPlaceholderText("New vault passphrase…")
        pp_layout.addWidget(self._master_pp)
        pp_layout.addWidget(QLabel("Confirm vault passphrase:"))
        self._confirm_pp = PassphraseField(show_strength=False)
        self._confirm_pp.setPlaceholderText("Repeat vault passphrase…")
        pp_layout.addWidget(self._confirm_pp)
        self._pp_mismatch = QLabel("")
        self._pp_mismatch.setStyleSheet("color: #cc0000;")
        pp_layout.addWidget(self._pp_mismatch)
        pp_layout.addWidget(QLabel("GPG key passphrase (to decrypt private keys for export):"))
        self._gpg_pp = PassphraseField(show_strength=False)
        self._gpg_pp.setPlaceholderText("Passphrase for your GPG private keys…")
        pp_layout.addWidget(self._gpg_pp)
        layout.addWidget(pp_box)

        btn_row = QHBoxLayout()
        self._btn_export = QPushButton("Create Vault")
        self._btn_export.setEnabled(False)
        btn_row.addWidget(self._btn_export)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedHeight(4)
        self._progress.hide()
        layout.addWidget(self._progress)

        self._error_label = QLabel()
        self._error_label.setStyleSheet("color: #cc0000;")
        self._error_label.setWordWrap(True)
        self._error_label.hide()
        layout.addWidget(self._error_label)

        self._result_label = QLabel()
        self._result_label.setWordWrap(True)
        self._result_label.hide()
        layout.addWidget(self._result_label)

        layout.addStretch()

    def _connect_signals(self) -> None:
        self._vm.keys_loaded.connect(self._on_keys_loaded)
        self._vm.loading_changed.connect(self._on_loading)
        self._vm.operation_succeeded.connect(self._on_success)
        self._vm.operation_failed.connect(self._on_error)

        self._key_list.itemSelectionChanged.connect(self._on_key_selection)
        self._btn_browse.clicked.connect(self._browse)
        self._path_field.textChanged.connect(self._on_path_changed)
        self._desc_field.textChanged.connect(self._vm.set_description)
        self._master_pp.passphrase_changed.connect(self._on_master_changed)
        self._confirm_pp.passphrase_changed.connect(self._on_confirm_changed)
        self._gpg_pp.passphrase_changed.connect(self._on_gpg_changed)
        self._btn_export.clicked.connect(self._vm.submit)

    def _on_keys_loaded(self, keys: list[KeyInfo]) -> None:
        self._key_list.clear()
        for key in keys:
            uid = key.user_ids[0] if key.user_ids else key.fingerprint[-16:]
            item = QListWidgetItem(f"{uid}  [{key.fingerprint[-16:]}]")
            item.setData(0x0100, key.fingerprint)  # Qt.ItemDataRole.UserRole
            self._key_list.addItem(item)

    def _on_key_selection(self) -> None:
        fps = [
            item.data(0x0100)
            for item in self._key_list.selectedItems()
            if item.data(0x0100)
        ]
        self._vm.set_selected(fps)
        self._update_button()

    def _browse(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Vault File",
            "",
            "GPG Meister Vault (*.gpgm);;All Files (*)",
        )
        if path:
            if not path.endswith(".gpgm"):
                path += ".gpgm"
            self._path_field.setText(path)

    def _on_path_changed(self, text: str) -> None:
        self._vm.set_target_path(Path(text) if text else None)
        self._update_button()

    def _on_master_changed(self) -> None:
        self._vm.set_master_passphrase(self._master_pp.text())
        self._check_pp_match()
        self._update_button()

    def _on_confirm_changed(self) -> None:
        self._vm.set_confirm_passphrase(self._confirm_pp.text())
        self._check_pp_match()
        self._update_button()

    def _on_gpg_changed(self) -> None:
        self._vm.set_gpg_passphrase(self._gpg_pp.text())
        self._update_button()

    def _check_pp_match(self) -> None:
        a = self._master_pp.text()
        b = self._confirm_pp.text()
        if b and a != b:
            self._pp_mismatch.setText("Passphrases do not match.")
        else:
            self._pp_mismatch.setText("")

    def _update_button(self) -> None:
        self._btn_export.setEnabled(self._vm.can_submit())

    def _on_loading(self, loading: bool) -> None:
        if loading:
            self._progress.show()
        else:
            self._progress.hide()
        self._btn_export.setEnabled(not loading and self._vm.can_submit())
        self._btn_browse.setEnabled(not loading)

    def _on_success(self, result: object) -> None:
        if not isinstance(result, VaultDescriptor):
            return
        self._error_label.hide()
        self._result_label.setText(
            f"Vault created successfully.\n"
            f"File: {result.path}\n"
            f"Keys: {result.key_count}\n"
            f"SHA-256: {result.sha256[:32]}…"
        )
        self._result_label.setStyleSheet("color: #006600;")
        self._result_label.show()

    def _on_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.show()
        self._result_label.hide()
