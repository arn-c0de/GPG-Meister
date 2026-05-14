"""Key list view — the Keys tab (planv2.md §4.8)."""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.ui.keys.key_create_view import KeyCreateDialog
from gpg_meister.ui.keys.key_detail_view import KeyDetailView
from gpg_meister.ui.keys.key_list_viewmodel import KeyListViewModel
from gpg_meister.ui.keys.public_key_import_view import PublicKeyImportDialog

_COL_FAV = 0
_COL_UID = 1
_COL_ALGO = 2
_COL_FP = 3
_COL_CREATED = 4
_COL_EXPIRES = 5
_COL_HAS_PRIV = 6
_COL_TRUST = 7

_STAR_ON = "★"
_STAR_OFF = "☆"
_TOTAL_COLS = 8


def _fmt_date(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d")


def _is_expired(key: KeyInfo) -> bool:
    if key.expires_at is None:
        return False
    return datetime.now(tz=UTC) >= key.expires_at


class _KeyTableWidget(QTableWidget):
    """Clears selection when the user clicks below or beside the last row."""

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self.itemAt(_event_pos(event)) is None:
            self.clearSelection()
            self.setCurrentItem(None)
        super().mousePressEvent(event)


class KeyListView(QWidget):
    _DELETE_CONFIRM_TEXT = "DELETE"

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

        self._table = _KeyTableWidget(0, _TOTAL_COLS)
        self._table.setHorizontalHeaderLabels(
            ["", "User ID", "Algorithm", "Fingerprint", "Created", "Expires", "Private", "Trust"]
        )
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        hh = self._table.horizontalHeader()
        hh.setSectionResizeMode(_COL_FAV, QHeaderView.ResizeMode.Fixed)
        hh.resizeSection(_COL_FAV, 28)
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

        self._btn_create.clicked.connect(self._open_create_dialog)
        self._btn_import.clicked.connect(self._open_import_dialog)
        self._btn_delete.clicked.connect(self._delete_selected)
        self._btn_refresh.clicked.connect(self._vm.refresh)

        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.doubleClicked.connect(self._open_detail)
        self._table.cellClicked.connect(self._on_cell_clicked)

    def _on_keys_changed(self, keys: list[KeyInfo]) -> None:
        self._keys = keys
        self._table.setRowCount(len(keys))
        for row, key in enumerate(keys):
            fav_item = _cell(_STAR_ON if key.is_favorite else _STAR_OFF)
            fav_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if key.is_favorite:
                fav_item.setForeground(Qt.GlobalColor.yellow)
            else:
                fav_item.setForeground(Qt.GlobalColor.gray)
            self._table.setItem(row, _COL_FAV, fav_item)

            uid = _display_name(key)
            self._table.setItem(row, _COL_UID, _cell(uid))
            self._table.setItem(row, _COL_ALGO, _cell(key.algorithm.value))
            self._table.setItem(row, _COL_FP, _cell(key.fingerprint[-16:]))
            self._table.setItem(row, _COL_CREATED, _cell(_fmt_date(key.created_at)))
            self._table.setItem(row, _COL_EXPIRES, _cell(_fmt_date(key.expires_at)))
            self._table.setItem(row, _COL_HAS_PRIV, _cell("yes" if key.has_private_key else ""))
            self._table.setItem(row, _COL_TRUST, _cell(key.trust.value))

            if key.is_revoked or _is_expired(key):
                for col in range(_TOTAL_COLS):
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

    def _on_selection_changed(self) -> None:
        key = self._selected_key()
        if key is None:
            self._btn_delete.setEnabled(False)
            self._btn_delete.setToolTip("")
        elif key.is_favorite:
            self._btn_delete.setEnabled(False)
            self._btn_delete.setToolTip("Remove from favorites before deleting")
        else:
            self._btn_delete.setEnabled(True)
            self._btn_delete.setToolTip("")

    def _on_cell_clicked(self, row: int, col: int) -> None:
        if col != _COL_FAV:
            return
        if 0 <= row < len(self._keys):
            self._vm.toggle_favorite(self._keys[row].fingerprint)

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
        if key.is_favorite:
            QMessageBox.warning(
                self,
                "Delete blocked",
                "Remove the key from favorites (☆) before deleting it.",
            )
            return
        if key.has_private_key:
            if not self._confirm_delete(key, "Delete key pair"):
                return
            self._vm.request_delete(key.fingerprint, including_secret=True)
        else:
            if not self._confirm_delete(key, "Delete public key"):
                return
            self._vm.request_delete(key.fingerprint, including_secret=False)

    def _confirm_delete(self, key: KeyInfo, title: str) -> bool:
        if not self._vm.require_delete_text_confirmation:
            answer = QMessageBox.question(
                self,
                title,
                f"Permanently delete key {key.fingerprint[-16:]}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            return answer == QMessageBox.StandardButton.Yes

        confirmation, ok = QInputDialog.getText(
            self,
            title,
            f"Type DELETE to permanently remove key {key.fingerprint[-16:]}.",
        )
        return ok and confirmation.strip().upper() == self._DELETE_CONFIRM_TEXT

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


def _event_pos(event: QMouseEvent) -> QPoint:
    point = event.position()
    return QPoint(int(point.x()), int(point.y()))
