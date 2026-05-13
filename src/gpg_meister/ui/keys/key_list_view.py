"""Key list view — the Keys tab (planv2.md §4.8)."""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.ui.errors.user_error import ErrorSeverity
from gpg_meister.ui.keys.key_create_view import KeyCreateDialog
from gpg_meister.ui.keys.key_detail_view import KeyDetailView
from gpg_meister.ui.keys.key_list_viewmodel import KeyListViewModel
from gpg_meister.ui.keys.public_key_import_view import PublicKeyImportDialog
from gpg_meister.ui.widgets.warning_banner import WarningBanner

_COL_UID = 0
_COL_ALGO = 1
_COL_FP = 2
_COL_CREATED = 3
_COL_EXPIRES = 4
_COL_HAS_PRIV = 5
_COL_TRUST = 6


def _fmt_date(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d")


def _is_expired(key: KeyInfo) -> bool:
    if key.expires_at is None:
        return False
    return datetime.now(tz=UTC) >= key.expires_at


class KeyListView(QWidget):
    def __init__(self, viewmodel: KeyListViewModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vm = viewmodel
        self._keys: list[KeyInfo] = []
        self._build_ui()
        self._connect_signals()
        self._vm.refresh()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        self._backup_banner = WarningBanner(
            "You just created a new key. Create a vault backup so you can restore it later.",
            severity=ErrorSeverity.WARNING,
            dismissible=True,
        )
        self._backup_banner.hide()
        layout.addWidget(self._backup_banner)

        toolbar = QHBoxLayout()
        self._btn_create = QPushButton("New Key…")
        self._btn_import = QPushButton("Import Public Key…")
        self._btn_delete = QPushButton("Delete…")
        self._btn_delete.setEnabled(False)
        self._btn_refresh = QPushButton("Refresh")
        toolbar.addWidget(self._btn_create)
        toolbar.addWidget(self._btn_import)
        toolbar.addWidget(self._btn_delete)
        toolbar.addStretch()
        toolbar.addWidget(self._btn_refresh)
        layout.addLayout(toolbar)

        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels(
            ["User ID", "Algorithm", "Fingerprint", "Created", "Expires", "Private", "Trust"]
        )
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        hh = self._table.horizontalHeader()
        hh.setSectionResizeMode(_COL_UID, QHeaderView.ResizeMode.Stretch)
        for col in (_COL_ALGO, _COL_FP, _COL_CREATED, _COL_EXPIRES, _COL_HAS_PRIV, _COL_TRUST):
            hh.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self._table.verticalHeader().hide()
        layout.addWidget(self._table, stretch=1)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedHeight(4)
        self._progress.hide()
        layout.addWidget(self._progress)

        self._error_label = QLabel()
        self._error_label.setStyleSheet("color: #cc0000;")
        self._error_label.hide()
        layout.addWidget(self._error_label)

    def _connect_signals(self) -> None:
        self._vm.keys_changed.connect(self._on_keys_changed)
        self._vm.loading_changed.connect(self._on_loading)
        self._vm.operation_failed.connect(self._on_error)
        self._vm.key_created.connect(self._on_key_created)

        self._btn_create.clicked.connect(self._open_create_dialog)
        self._btn_import.clicked.connect(self._open_import_dialog)
        self._btn_delete.clicked.connect(self._delete_selected)
        self._btn_refresh.clicked.connect(self._vm.refresh)

        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.doubleClicked.connect(self._open_detail)

    def _on_keys_changed(self, keys: list[KeyInfo]) -> None:
        self._keys = keys
        self._table.setRowCount(len(keys))
        for row, key in enumerate(keys):
            uid = _display_name(key)
            self._table.setItem(row, _COL_UID, _cell(uid))
            self._table.setItem(row, _COL_ALGO, _cell(key.algorithm.value))
            self._table.setItem(row, _COL_FP, _cell(key.fingerprint[-16:]))
            self._table.setItem(row, _COL_CREATED, _cell(_fmt_date(key.created_at)))
            self._table.setItem(row, _COL_EXPIRES, _cell(_fmt_date(key.expires_at)))
            self._table.setItem(row, _COL_HAS_PRIV, _cell("yes" if key.has_private_key else ""))
            self._table.setItem(row, _COL_TRUST, _cell(key.trust.value))

            if key.is_revoked or _is_expired(key):
                for col in range(7):
                    item = self._table.item(row, col)
                    if item:
                        item.setForeground(Qt.GlobalColor.gray)

    def _on_loading(self, loading: bool) -> None:
        if loading:
            self._progress.show()
        else:
            self._progress.hide()
        self._btn_create.setEnabled(not loading)
        self._btn_import.setEnabled(not loading)
        self._btn_refresh.setEnabled(not loading)

    def _on_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.show()

    def _on_key_created(self, key: KeyInfo) -> None:
        uid = key.user_ids[0] if key.user_ids else key.fingerprint[-16:]
        self._backup_banner.set_message(
            f'New key "{uid}" created. Create a vault backup so you can restore it later.'
        )
        self._backup_banner.show()

    def _on_selection_changed(self) -> None:
        has_sel = bool(self._table.selectedItems())
        self._btn_delete.setEnabled(has_sel)

    def _selected_key(self) -> KeyInfo | None:
        rows = self._table.selectedItems()
        if not rows:
            return None
        row = self._table.currentRow()
        if 0 <= row < len(self._keys):
            return self._keys[row]
        return None

    def _open_create_dialog(self) -> None:

        dlg = KeyCreateDialog(self._vm._svc, parent=self)
        dlg.key_created.connect(self._vm.notify_key_created)
        dlg.exec()

    def _open_import_dialog(self) -> None:
        dlg = PublicKeyImportDialog(self._vm._svc, parent=self)
        dlg.exec()
        self._vm.refresh()

    def _delete_selected(self) -> None:
        key = self._selected_key()
        if key is None:
            return
        from PySide6.QtWidgets import QInputDialog, QMessageBox

        if key.has_private_key:
            passphrase_text, ok = QInputDialog.getText(
                self,
                "Delete key pair",
                f"Enter the passphrase for key {key.fingerprint[-16:]} to confirm deletion:",
                echo=QLineEdit.EchoMode.Password,
            )
            if not ok or not passphrase_text:
                return
            with SecureBytes.from_bytes(passphrase_text.encode()) as pp:
                self._vm.request_delete(
                    key.fingerprint, including_secret=True, passphrase=pp
                )
        else:
            answer = QMessageBox.question(
                self,
                "Delete public key",
                f"Delete public key {key.fingerprint[-16:]}?",
            )
            if answer == QMessageBox.StandardButton.Yes:
                self._vm.request_delete(key.fingerprint, including_secret=False)

    def _open_detail(self) -> None:
        key = self._selected_key()
        if key is None:
            return
        dlg = KeyDetailView(key, self._vm._svc, parent=self)
        dlg.key_updated.connect(lambda _updated: self._vm.refresh())
        dlg.exec()


def _cell(text: str) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item


def _display_name(key: KeyInfo) -> str:
    primary_uid = key.user_ids[0] if key.user_ids else "—"
    if not key.label:
        return primary_uid
    return f"{key.label} | {primary_uid}"
