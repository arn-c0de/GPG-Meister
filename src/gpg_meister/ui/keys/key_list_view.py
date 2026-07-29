"""Key list view — the Keys tab (planv2.md §4.8)."""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo, KeyStorage
from gpg_meister.services.smartcard_service import CardSyncResult
from gpg_meister.ui.keys.key_create_view import KeyCreateDialog
from gpg_meister.ui.keys.key_detail_view import KeyDetailView
from gpg_meister.ui.keys.key_list_viewmodel import KeyListViewModel
from gpg_meister.ui.keys.public_key_import_view import PublicKeyImportDialog
from gpg_meister.ui.qt_helpers import busy_bar, error_label, read_only_cell

_COL_FAV = 0
_COL_UID = 1
_COL_ALGO = 2
_COL_FP = 3
_COL_CREATED = 4
_COL_EXPIRES = 5
_COL_STORAGE = 6
_COL_TRUST = 7

_STAR_ON = "★"
_STAR_OFF = "☆"
_TOTAL_COLS = 8

# Tooltip per storage kind — the column text alone ("YubiKey 12345678") does not
# say what it implies for the user.
_STORAGE_TOOLTIPS: dict[KeyStorage, str] = {
    KeyStorage.SMARTCARD: (
        "This key lives on a hardware token. Plug it in and enter its PIN to decrypt "
        "or sign; whatever the device holds can never be exported off it."
    ),
    KeyStorage.LOCAL: "The private key is stored on this computer, protected by its passphrase.",
    KeyStorage.OFFLINE: (
        "GnuPG knows this secret key but does not have it here — it is on another "
        "machine, or on a token that has not been linked yet."
    ),
    KeyStorage.PUBLIC_ONLY: "Public key only — you can encrypt to it and verify its signatures.",
}


def _fmt_date(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d")


class _KeyTableWidget(QTableWidget):
    """Clears selection when the user clicks below or beside the last row."""

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton and self.itemAt(_event_pos(event)) is None:
            self.clearSelection()
            self.setCurrentCell(-1, -1)
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
        self._vm.refresh_card()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        toolbar = QHBoxLayout()
        self._btn_create = QPushButton("New Key…")
        self._btn_import = QPushButton("Import Public Key…")
        self._btn_delete = QPushButton("Delete…")
        self._btn_delete.setEnabled(False)
        self._btn_smartcard = QPushButton("Smartcard…")
        self._btn_smartcard.setToolTip("Inspect and link an inserted YubiKey or OpenPGP card")
        self._btn_smartcard.setVisible(self._vm.smartcard_service is not None)
        self._btn_refresh = QPushButton("Refresh")
        toolbar.addWidget(self._btn_create)
        toolbar.addWidget(self._btn_import)
        toolbar.addWidget(self._btn_delete)
        toolbar.addWidget(self._btn_smartcard)
        toolbar.addStretch()
        self._card_status = QLabel()
        self._card_status.setStyleSheet("color: #666666;")
        self._card_status.setVisible(self._vm.smartcard_service is not None)
        toolbar.addWidget(self._card_status)
        toolbar.addWidget(self._btn_refresh)
        layout.addLayout(toolbar)

        self._table = _KeyTableWidget(0, _TOTAL_COLS)
        self._table.setHorizontalHeaderLabels(
            ["", "User ID", "Algorithm", "Fingerprint", "Created", "Expires", "Storage", "Trust"]
        )
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        hh = self._table.horizontalHeader()
        hh.setSectionResizeMode(_COL_FAV, QHeaderView.ResizeMode.Fixed)
        hh.resizeSection(_COL_FAV, 28)
        hh.setSectionResizeMode(_COL_UID, QHeaderView.ResizeMode.Stretch)
        for col in (_COL_ALGO, _COL_FP, _COL_CREATED, _COL_EXPIRES, _COL_STORAGE, _COL_TRUST):
            hh.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self._table.verticalHeader().hide()
        layout.addWidget(self._table, stretch=1)

        self._progress = busy_bar()
        layout.addWidget(self._progress)

        self._error_label = error_label(word_wrap=False)
        layout.addWidget(self._error_label)

    def _connect_signals(self) -> None:
        self._vm.keys_changed.connect(self._on_keys_changed)
        self._vm.loading_changed.connect(self._on_loading)
        self._vm.operation_failed.connect(self._on_error)
        self._vm.card_changed.connect(self._on_card_changed)

        self._btn_create.clicked.connect(self._open_create_dialog)
        self._btn_import.clicked.connect(self._open_import_dialog)
        self._btn_delete.clicked.connect(self._delete_selected)
        self._btn_smartcard.clicked.connect(self._open_smartcard_dialog)
        self._btn_refresh.clicked.connect(self._refresh_all)

        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        self._table.doubleClicked.connect(self._open_detail)
        self._table.cellClicked.connect(self._on_cell_clicked)

    def _on_keys_changed(self, keys: list[KeyInfo]) -> None:
        self._keys = keys
        self._table.setRowCount(len(keys))
        for row, key in enumerate(keys):
            fav_item = read_only_cell(_STAR_ON if key.is_favorite else _STAR_OFF)
            fav_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if key.is_favorite:
                fav_item.setForeground(Qt.GlobalColor.yellow)
            else:
                fav_item.setForeground(Qt.GlobalColor.gray)
            self._table.setItem(row, _COL_FAV, fav_item)

            uid = _display_name(key)
            self._table.setItem(row, _COL_UID, read_only_cell(uid))
            self._table.setItem(row, _COL_ALGO, read_only_cell(key.algorithm.value))
            self._table.setItem(row, _COL_FP, read_only_cell(key.fingerprint[-16:]))
            self._table.setItem(row, _COL_CREATED, read_only_cell(_fmt_date(key.created_at)))
            self._table.setItem(row, _COL_EXPIRES, read_only_cell(_fmt_date(key.expires_at)))
            storage_item = read_only_cell(key.storage_label)
            storage_item.setToolTip(_STORAGE_TOOLTIPS.get(key.storage, ""))
            if key.is_on_smartcard:
                storage_item.setForeground(Qt.GlobalColor.darkCyan)
            self._table.setItem(row, _COL_STORAGE, storage_item)
            self._table.setItem(row, _COL_TRUST, read_only_cell(key.trust.value))

            if key.is_revoked or key.is_expired:
                for col in range(_TOTAL_COLS):
                    item = self._table.item(row, col)
                    if item:
                        item.setForeground(Qt.GlobalColor.gray)

    def _on_loading(self, loading: bool) -> None:
        self._progress.setVisible(loading)
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

    def _refresh_all(self) -> None:
        self._vm.refresh()
        self._vm.refresh_card()

    def _open_smartcard_dialog(self) -> None:
        smartcard = self._vm.smartcard_service
        if smartcard is None:
            return
        from gpg_meister.ui.keys.smartcard_view import SmartcardDialog

        dlg = SmartcardDialog(smartcard, self._vm._svc, parent=self)
        dlg.keyring_changed.connect(self._vm.refresh)
        dlg.exec()
        self._refresh_all()

    def _on_card_changed(self, result: object) -> None:
        if not isinstance(result, CardSyncResult):
            self._card_status.clear()
            return
        if result.card is None:
            self._card_status.setText("No smartcard")
            self._card_status.setToolTip(
                result.unavailable_reason
                or "No YubiKey or OpenPGP card is currently readable."
            )
            self._card_status.setStyleSheet("color: #666666;")
            return
        self._card_status.setText(f"{result.card.display_name} connected")
        self._card_status.setToolTip(
            "Keys held on this token are marked in the Storage column. "
            "Unlock them with the card PIN instead of a passphrase."
        )
        self._card_status.setStyleSheet("color: #006600;")

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
        # Deleting a card-backed key only drops the local stub; the token keeps
        # the key material, so say so rather than let "permanently" mislead.
        note = (
            f"\n\nThis removes only the local reference — the key stays on "
            f"{key.storage_label} and can be linked again."
            if key.is_on_smartcard
            else ""
        )
        if not self._vm.require_delete_text_confirmation:
            answer = QMessageBox.question(
                self,
                title,
                f"Permanently delete key {key.fingerprint[-16:]}?{note}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            return answer == QMessageBox.StandardButton.Yes

        confirmation, ok = QInputDialog.getText(
            self,
            title,
            f"Type DELETE to permanently remove key {key.fingerprint[-16:]}.{note}",
        )
        return ok and confirmation.strip().upper() == self._DELETE_CONFIRM_TEXT

    def _open_detail(self) -> None:
        key = self._selected_key()
        if key is None:
            return
        dlg = KeyDetailView(key, self._vm._svc, parent=self)
        dlg.key_updated.connect(lambda _updated: self._vm.refresh())
        dlg.exec()


def _display_name(key: KeyInfo) -> str:
    primary_uid = key.primary_user_id
    if not key.label:
        return primary_uid
    return f"{key.label} | {primary_uid}"


def _event_pos(event: QMouseEvent) -> QPoint:
    point = event.position()
    return QPoint(int(point.x()), int(point.y()))
