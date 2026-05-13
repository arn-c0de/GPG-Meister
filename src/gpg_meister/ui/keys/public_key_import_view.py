"""Public-key import dialog with conflict plan display (planv2.md §14)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.services.key_service import ImportConflict, ImportPlanEntry, KeyService

_CONFLICT_LABELS: dict[ImportConflict, str] = {
    ImportConflict.NEW: "New — will be imported",
    ImportConflict.ALREADY_PRESENT: "Already in keyring (public)",
    ImportConflict.ALREADY_HAS_PRIVATE: "Already present with private key",
}


class PublicKeyImportDialog(QDialog):
    """Paste or load armored public key(s), preview the import plan, then import."""

    def __init__(self, key_service: KeyService, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Import Public Key")
        self.setMinimumSize(560, 420)
        self._svc = key_service
        self._plan: tuple[ImportPlanEntry, ...] = ()
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Paste an armored public key block or load from file:"))

        self._text_edit = QPlainTextEdit()
        self._text_edit.setPlaceholderText("-----BEGIN PGP PUBLIC KEY BLOCK-----\n…")
        self._text_edit.setMinimumHeight(120)
        self._text_edit.setMaximumHeight(160)
        layout.addWidget(self._text_edit)

        file_row = QHBoxLayout()
        self._load_btn = QPushButton("Load from file…")
        self._load_btn.clicked.connect(self._load_file)
        self._analyze_btn = QPushButton("Analyze")
        self._analyze_btn.clicked.connect(self._analyze)
        file_row.addWidget(self._load_btn)
        file_row.addWidget(self._analyze_btn)
        file_row.addStretch()
        layout.addLayout(file_row)

        layout.addWidget(QLabel("Import plan:"))
        self._plan_table = QTableWidget(0, 3)
        self._plan_table.setHorizontalHeaderLabels(["Fingerprint", "User IDs", "Status"])
        self._plan_table.horizontalHeader().setStretchLastSection(True)
        self._plan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._plan_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self._plan_table, stretch=1)

        self._error_label = QLabel("")
        self._error_label.setStyleSheet("color: #cc0000;")
        self._error_label.setWordWrap(True)
        self._error_label.hide()
        layout.addWidget(self._error_label)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Import")
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        self._buttons.accepted.connect(self._do_import)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

    def _load_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Public Key File", "", "Armored keys (*.asc *.gpg *.key);;All files (*)"
        )
        if path:
            try:
                self._text_edit.setPlainText(Path(path).read_text("utf-8"))
            except Exception as exc:
                self._show_error(f"Could not read file: {exc}")

    def _analyze(self) -> None:
        armored = self._text_edit.toPlainText().strip()
        if not armored:
            self._show_error("No key data entered.")
            return
        self._error_label.hide()
        try:
            self._plan = self._svc.plan_import(armored)
        except Exception as exc:
            self._show_error(f"Could not analyze key: {exc}")
            return

        self._plan_table.setRowCount(len(self._plan))
        has_new = False
        for row, entry in enumerate(self._plan):
            self._plan_table.setItem(row, 0, _cell(entry.fingerprint[-16:]))
            self._plan_table.setItem(row, 1, _cell(", ".join(entry.user_ids)))
            status = _CONFLICT_LABELS.get(entry.conflict, entry.conflict.value)
            cell = _cell(status)
            if entry.conflict == ImportConflict.NEW:
                has_new = True
            else:
                cell.setForeground(Qt.GlobalColor.gray)
            self._plan_table.setItem(row, 2, cell)

        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(has_new)
        if not has_new:
            self._show_error("All keys are already in the keyring.")

    def _do_import(self) -> None:
        armored = self._text_edit.toPlainText().strip()
        if not armored:
            return
        try:
            imported = self._svc.import_armored(armored)
            count = len(imported)
            self._show_error("")
        except Exception as exc:
            self._show_error(f"Import failed: {exc}")
            return
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.information(self, "Import complete", f"Imported {count} key(s).")
        self.accept()

    def _show_error(self, msg: str) -> None:
        if msg:
            self._error_label.setText(msg)
            self._error_label.show()
        else:
            self._error_label.hide()


def _cell(text: str) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item
