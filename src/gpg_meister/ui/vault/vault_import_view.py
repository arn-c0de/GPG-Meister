"""Vault import wizard (planv2.md §14.4)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
)

from gpg_meister.models.vault import VaultKeyEntry
from gpg_meister.security.errors import DecryptionError, VaultFormatError
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.security.vault_format import MAGIC
from gpg_meister.services.vault_service import VaultChecksumMismatchError, VaultPreview, VaultService
from gpg_meister.ui.widgets.passphrase_field import PassphraseField

_PAGE_FILE = 0
_PAGE_PREVIEW = 1
_PAGE_SELECT = 2
_PAGE_RESULT = 3


class _FilePage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Select vault file")
        self.setSubTitle("Choose the .gpgm vault file to import from.")
        layout = QVBoxLayout(self)

        path_row = QHBoxLayout()
        self._path_field = QLineEdit()
        self._path_field.setPlaceholderText("Vault file path…")
        self._path_field.setReadOnly(True)
        self._btn_browse = QPushButton("Browse…")
        path_row.addWidget(self._path_field, stretch=1)
        path_row.addWidget(self._btn_browse)
        layout.addLayout(path_row)

        self._info_label = QLabel()
        self._info_label.setWordWrap(True)
        layout.addWidget(self._info_label)

        layout.addStretch()

        self._btn_browse.clicked.connect(self._browse)
        self._path_field.textChanged.connect(self._on_path_changed)
        self.registerField("vault_path*", self._path_field)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Vault File",
            "",
            "GPG Meister Vault (*.gpgm);;All Files (*)",
        )
        if path:
            self._path_field.setText(path)

    def _on_path_changed(self, text: str) -> None:
        p = Path(text)
        if not p.exists():
            self._info_label.setText("")
            self._info_label.setStyleSheet("")
            return
        try:
            data = p.read_bytes()[: len(MAGIC)]
            if data != MAGIC:
                self._info_label.setText("This does not appear to be a valid GPG Meister vault file.")
                self._info_label.setStyleSheet("color: #cc0000;")
            else:
                size_kb = p.stat().st_size // 1024
                self._info_label.setText(f"Valid vault format detected.  Size: {size_kb} KB")
                self._info_label.setStyleSheet("color: #006600;")
        except OSError as exc:
            self._info_label.setText(f"Cannot read file: {exc}")
            self._info_label.setStyleSheet("color: #cc0000;")
        self.completeChanged.emit()

    def isComplete(self) -> bool:
        text = self._path_field.text()
        if not text:
            return False
        p = Path(text)
        return p.exists() and p.is_file()


class _PassphrasePage(QWizardPage):
    def __init__(self, vault_svc: VaultService) -> None:
        super().__init__()
        self.setTitle("Enter vault passphrase")
        self.setSubTitle(
            "Enter the master passphrase for this vault. "
            "The vault will be decrypted to preview its contents."
        )
        self._vault_svc = vault_svc
        self._preview: VaultPreview | None = None

        layout = QVBoxLayout(self)
        self._pp_field = PassphraseField(show_strength=False)
        self._pp_field.setPlaceholderText("Vault master passphrase…")
        layout.addWidget(QLabel("Master passphrase:"))
        layout.addWidget(self._pp_field)

        self._status_label = QLabel()
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)
        layout.addStretch()


    def preview(self) -> VaultPreview | None:
        return self._preview

    def passphrase(self) -> str:
        return self._pp_field.text()

    def validatePage(self) -> bool:
        vault_path = Path(self.field("vault_path"))
        pp_text = self._pp_field.text()
        if not pp_text:
            self._status_label.setText("Passphrase is required.")
            self._status_label.setStyleSheet("color: #cc0000;")
            return False
        self._status_label.setText("Decrypting vault… (this may take a moment)")
        self._status_label.setStyleSheet("color: #666666;")
        # processEvents to show the status label before blocking
        from PySide6.QtWidgets import QApplication
        QApplication.processEvents()
        try:
            with SecureBytes.from_bytes(pp_text.encode()) as pp:
                self._preview = self._vault_svc.preview(
                    source_path=vault_path, master_passphrase=pp
                )
            self._status_label.setText("Vault decrypted successfully.")
            self._status_label.setStyleSheet("color: #006600;")
            return True
        except VaultChecksumMismatchError:
            from PySide6.QtWidgets import QMessageBox
            reply = QMessageBox.warning(
                self,
                "Vault Checksum Mismatch",
                "The vault's checksum does not match.\n"
                "The file may have been damaged during transfer.\n\n"
                "The vault content is cryptographically intact (AEAD verified).\n"
                "Open it anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                self._status_label.setText("Import cancelled.")
                self._status_label.setStyleSheet("color: #666666;")
                return False
            with SecureBytes.from_bytes(pp_text.encode()) as pp:
                self._preview = self._vault_svc.preview(
                    source_path=vault_path, master_passphrase=pp, skip_checksum=True
                )
            self._status_label.setText("Vault opened (checksum ignored).")
            self._status_label.setStyleSheet("color: #cc6600;")
            return True
        except DecryptionError:
            self._status_label.setText("Wrong passphrase or corrupted vault.")
            self._status_label.setStyleSheet("color: #cc0000;")
            return False
        except VaultFormatError as exc:
            self._status_label.setText(f"Invalid vault format: {exc}")
            self._status_label.setStyleSheet("color: #cc0000;")
            return False
        except Exception:
            self._status_label.setText("Error: the vault could not be opened.")
            self._status_label.setStyleSheet("color: #cc0000;")
            return False


class _SelectPage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Select keys to import")
        self.setSubTitle("Choose which keys from the vault to import into your keyring.")
        self._keys: tuple[VaultKeyEntry, ...] = ()

        layout = QVBoxLayout(self)
        self._meta_label = QLabel()
        self._meta_label.setTextFormat(Qt.TextFormat.PlainText)
        self._meta_label.setWordWrap(True)
        layout.addWidget(self._meta_label)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["User ID", "Fingerprint", "Has private key", "Expires"])
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.verticalHeader().hide()
        layout.addWidget(self._table, stretch=1)

        sel_row = QHBoxLayout()
        btn_all = QPushButton("Select All")
        btn_none = QPushButton("Select None")
        btn_all.clicked.connect(self._table.selectAll)
        btn_none.clicked.connect(self._table.clearSelection)
        sel_row.addWidget(btn_all)
        sel_row.addWidget(btn_none)
        sel_row.addStretch()
        layout.addLayout(sel_row)

        self._table.itemSelectionChanged.connect(self.completeChanged.emit)

    def initializePage(self) -> None:
        pp_page = self.wizard().page(_PAGE_PREVIEW)
        if not isinstance(pp_page, _PassphrasePage):
            return
        preview = pp_page.preview()
        if preview is None:
            return
        self._keys = preview.keys
        self._meta_label.setText(
            f"Vault created: {preview.created_at.strftime('%Y-%m-%d %H:%M UTC')}  |  "
            f"App version: {preview.app_version}  |  "
            f"Description: {preview.description or '(none)'}"
        )
        self._table.setRowCount(len(self._keys))
        for row, entry in enumerate(self._keys):
            uid = entry.user_ids[0] if entry.user_ids else "—"
            exp = entry.expires_at.strftime("%Y-%m-%d") if entry.expires_at else "no expiry"
            self._table.setItem(row, 0, _cell(uid))
            self._table.setItem(row, 1, _cell(entry.fingerprint[-16:]))
            self._table.setItem(row, 2, _cell("yes" if entry.has_private_key else ""))
            self._table.setItem(row, 3, _cell(exp))
        self._table.selectAll()

    def selected_fingerprints(self) -> list[str]:
        rows = {idx.row() for idx in self._table.selectedIndexes()}
        return [self._keys[r].fingerprint for r in sorted(rows) if r < len(self._keys)]

    def isComplete(self) -> bool:
        return bool({idx.row() for idx in self._table.selectedIndexes()})


class _ResultPage(QWizardPage):
    def __init__(self, vault_svc: VaultService) -> None:
        super().__init__()
        self.setTitle("Import complete")
        self._vault_svc = vault_svc
        self._imported: list[str] = []

        layout = QVBoxLayout(self)
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        layout.addWidget(self._log)

    def initializePage(self) -> None:
        wizard = self.wizard()
        pp_page = wizard.page(_PAGE_PREVIEW)
        sel_page = wizard.page(_PAGE_SELECT)
        if not isinstance(pp_page, _PassphrasePage) or not isinstance(sel_page, _SelectPage):
            return

        preview = pp_page.preview()
        if preview is None:
            self._log.setPlainText("No vault preview available.")
            return

        fps = sel_page.selected_fingerprints()
        if not fps:
            self._log.setPlainText("No keys were selected.")
            return

        vault_path = Path(self.field("vault_path"))
        pp_text = pp_page.passphrase()

        self._log.setPlainText("Importing keys…")
        from PySide6.QtWidgets import QApplication
        QApplication.processEvents()

        lines: list[str] = []
        try:
            with SecureBytes.from_bytes(pp_text.encode()) as pp:
                imported = self._vault_svc.import_keys(
                    source_path=vault_path,
                    master_passphrase=pp,
                    fingerprints=fps,
                )
            self._imported = imported
            lines.append(f"Successfully imported {len(imported)} key(s):\n")
            for fp in imported:
                lines.append(f"  • {fp}")
        except Exception:
            lines.append("Import failed.")
        finally:
            pp_page._pp_field.clear()
        self._log.setPlainText("\n".join(lines))

    def imported_fingerprints(self) -> list[str]:
        return list(self._imported)


class VaultImportWizard(QWizard):
    """Multi-step vault import wizard (planv2.md §14.4)."""

    def __init__(
        self,
        vault_service: VaultService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Import from Vault")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setMinimumSize(640, 480)

        self._file_page = _FilePage()
        self._pp_page = _PassphrasePage(vault_service)
        self._select_page = _SelectPage()
        self._result_page = _ResultPage(vault_service)

        self.addPage(self._file_page)
        self.addPage(self._pp_page)
        self.addPage(self._select_page)
        self.addPage(self._result_page)

    def imported_fingerprints(self) -> list[str]:
        return self._result_page.imported_fingerprints()


def _cell(text: str) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item
