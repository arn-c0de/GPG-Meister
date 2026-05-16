"""Vault export view (planv2.md §4.8, §14.3)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
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

_COLOR_UNLOCKED = QColor("#1a7a1a")
_COLOR_LOCKED   = QColor("#8a4a00")
_COLOR_STUB     = QColor("#444444")


class VaultExportView(QWidget):
    """Export tab: select keys, unlock each key, choose file, create vault."""

    def __init__(
        self, viewmodel: VaultExportViewModel, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._vm = viewmodel
        self._active_fp: str | None = None
        self._build_ui()
        self._connect_signals()
        self._vm.load_keys()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Key selection list
        key_box = QGroupBox("Keys to include in vault")
        key_layout = QVBoxLayout(key_box)
        key_layout.addWidget(QLabel(
            "Select keys (Ctrl+click for multiple). Click a key to enter its passphrase."
        ))
        self._key_list = QListWidget()
        self._key_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        key_layout.addWidget(self._key_list)
        layout.addWidget(key_box)

        # Per-key unlock panel
        unlock_box = QGroupBox("Unlock key for export")
        unlock_layout = QVBoxLayout(unlock_box)
        self._unlock_label = QLabel("Click a key above to enter its passphrase.")
        self._unlock_label.setWordWrap(True)
        unlock_layout.addWidget(self._unlock_label)
        unlock_row = QHBoxLayout()
        self._unlock_pp = PassphraseField(show_strength=False)
        self._unlock_pp.setPlaceholderText("Key passphrase…")
        self._unlock_pp.setEnabled(False)
        self._btn_unlock = QPushButton("Unlock")
        self._btn_unlock.setEnabled(False)
        unlock_row.addWidget(self._unlock_pp, stretch=1)
        unlock_row.addWidget(self._btn_unlock)
        unlock_layout.addLayout(unlock_row)
        stub_hint = QLabel(
            "Smartcard keys (YubiKey etc.) are included as public-key only — no passphrase needed."
        )
        stub_hint.setWordWrap(True)
        stub_hint.setStyleSheet("font-size: 10px; color: #666666;")
        unlock_layout.addWidget(stub_hint)
        layout.addWidget(unlock_box)

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
        self._desc_field.setPlaceholderText("e.g. Home workstation backup 2026-05-15")
        desc_layout.addWidget(self._desc_field)
        layout.addWidget(desc_box)

        # Vault master passphrase
        pp_box = QGroupBox("Vault master passphrase")
        pp_layout = QVBoxLayout(pp_box)
        pp_layout.addWidget(QLabel("New passphrase to encrypt this vault:"))
        self._master_pp = PassphraseField(show_strength=True)
        self._master_pp.setPlaceholderText("Vault passphrase…")
        pp_layout.addWidget(self._master_pp)
        pp_layout.addWidget(QLabel("Confirm passphrase:"))
        self._confirm_pp = PassphraseField(show_strength=False)
        self._confirm_pp.setPlaceholderText("Repeat vault passphrase…")
        pp_layout.addWidget(self._confirm_pp)
        self._pp_mismatch = QLabel("")
        self._pp_mismatch.setStyleSheet("color: #cc0000;")
        pp_layout.addWidget(self._pp_mismatch)
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
        self._vm.key_unlock_state_changed.connect(self._on_key_unlock_changed)

        self._key_list.itemSelectionChanged.connect(self._on_key_selection)
        self._key_list.itemClicked.connect(self._on_item_clicked)
        self._btn_browse.clicked.connect(self._browse)
        self._path_field.textChanged.connect(self._on_path_changed)
        self._desc_field.textChanged.connect(self._vm.set_description)
        self._master_pp.passphrase_changed.connect(self._on_master_changed)
        self._confirm_pp.passphrase_changed.connect(self._on_confirm_changed)
        self._unlock_pp.passphrase_changed.connect(self._on_unlock_pp_changed)
        self._btn_unlock.clicked.connect(self._on_unlock_clicked)
        self._btn_export.clicked.connect(self._submit)

    # ------------------------------------------------------------------ keys

    def _on_keys_loaded(self, keys: list[KeyInfo]) -> None:
        self._key_list.clear()
        for key in keys:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, key.fingerprint)
            item.setData(Qt.ItemDataRole.UserRole + 1, key.is_stub)
            self._refresh_item_text(item, key.fingerprint, unlocked=False, is_stub=key.is_stub)
            self._key_list.addItem(item)

    def _refresh_item_text(
        self, item: QListWidgetItem, fp: str, *, unlocked: bool, is_stub: bool
    ) -> None:
        # Look up display name from the list itself (stored in UserRole data context).
        # Fall back to a safe short fingerprint label.
        raw = item.text()
        # Strip any previous prefix (first 2 chars are prefix + space).
        name_part = raw[2:] if len(raw) > 2 and raw[1] == " " else raw

        if is_stub:
            prefix = "☁ "  # ☁
            item.setForeground(_COLOR_STUB)
        elif unlocked:
            prefix = "✓ "  # ✓
            item.setForeground(_COLOR_UNLOCKED)
        else:
            prefix = "\U0001f512 "  # 🔒
            item.setForeground(_COLOR_LOCKED)

        item.setText(prefix + name_part)

    def _item_for_fp(self, fp: str) -> QListWidgetItem | None:
        for i in range(self._key_list.count()):
            item = self._key_list.item(i)
            if item and item.data(Qt.ItemDataRole.UserRole) == fp:
                return item
        return None

    def _on_key_unlock_changed(self, fp: str, unlocked: bool) -> None:
        item = self._item_for_fp(fp)
        if item is None:
            return
        is_stub = bool(item.data(Qt.ItemDataRole.UserRole + 1))
        self._refresh_item_text(item, fp, unlocked=unlocked, is_stub=is_stub)
        self._update_button()

    # --------------------------------------------------------- item init text

    def _init_item_name(self, item: QListWidgetItem, key: KeyInfo) -> None:
        uid = key.user_ids[0] if key.user_ids else key.fingerprint[-16:]
        short = key.fingerprint[-16:]
        name_part = f"{uid}  [{short}]"
        is_stub = key.is_stub
        prefix = "☁ " if is_stub else "\U0001f512 "
        color = _COLOR_STUB if is_stub else _COLOR_LOCKED
        item.setText(prefix + name_part)
        item.setForeground(color)

    def _on_keys_loaded(self, keys: list[KeyInfo]) -> None:  # type: ignore[override]
        self._key_list.clear()
        for key in keys:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, key.fingerprint)
            item.setData(Qt.ItemDataRole.UserRole + 1, key.is_stub)
            self._init_item_name(item, key)
            self._key_list.addItem(item)

    # -------------------------------------------------------------- selection

    def _on_key_selection(self) -> None:
        fps = [
            item.data(Qt.ItemDataRole.UserRole)
            for item in self._key_list.selectedItems()
            if item.data(Qt.ItemDataRole.UserRole)
        ]
        self._vm.set_selected(fps)
        self._update_button()

    def _on_item_clicked(self, item: QListWidgetItem) -> None:
        fp: str | None = item.data(Qt.ItemDataRole.UserRole)
        if not fp:
            return
        is_stub = bool(item.data(Qt.ItemDataRole.UserRole + 1))
        self._active_fp = fp
        uid_text = item.text()[2:]  # strip prefix
        if is_stub:
            self._unlock_label.setText(
                f"☁ {uid_text}\n(Smartcard key — public part only, no passphrase needed.)"
            )
            self._unlock_pp.setEnabled(False)
            self._btn_unlock.setEnabled(False)
        else:
            self._unlock_label.setText(f"Enter passphrase for:\n{uid_text}")
            self._unlock_pp.setEnabled(True)
            self._unlock_pp.clear()
            self._btn_unlock.setEnabled(False)
            self._unlock_pp.setFocus()

    # --------------------------------------------------------- unlock actions

    def _on_unlock_pp_changed(self) -> None:
        has_text = bool(self._unlock_pp.text())
        self._btn_unlock.setEnabled(has_text and self._active_fp is not None)
        if self._active_fp:
            self._vm.set_key_passphrase(self._active_fp, self._unlock_pp.text())

    def _on_unlock_clicked(self) -> None:
        if not self._active_fp:
            return
        fp = self._active_fp
        self._vm.set_key_passphrase(fp, self._unlock_pp.text())
        if self._vm.unlock_key(fp):
            # Null active_fp BEFORE clear() so the passphrase_changed signal that
            # clear() fires does not call set_key_passphrase(fp, "") and wipe the
            # passphrase we just stored.
            self._active_fp = None
            self._unlock_pp.clear()
            self._unlock_pp.setEnabled(False)
            self._btn_unlock.setEnabled(False)
            self._unlock_label.setText("✓ Unlocked — click another key to continue.")

    # ------------------------------------------------------------------ path

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

    # ----------------------------------------------------------- passphrases

    def _on_master_changed(self) -> None:
        self._vm.set_master_passphrase(self._master_pp.text())
        self._check_pp_match()
        self._update_button()

    def _on_confirm_changed(self) -> None:
        self._vm.set_confirm_passphrase(self._confirm_pp.text())
        self._check_pp_match()
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

    # ---------------------------------------------------------------- loading

    def _on_loading(self, loading: bool) -> None:
        if loading:
            self._progress.show()
        else:
            self._progress.hide()
        self._btn_export.setEnabled(not loading and self._vm.can_submit())
        self._btn_browse.setEnabled(not loading)

    # ---------------------------------------------------------------- results

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
        self._unlock_label.setText("Click a key above to enter its passphrase.")
        self._active_fp = None

    def _on_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.show()
        self._result_label.hide()

    def _submit(self) -> None:
        self._vm.submit()
        self._master_pp.clear()
        self._confirm_pp.clear()
