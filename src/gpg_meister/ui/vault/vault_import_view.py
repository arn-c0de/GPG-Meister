"""Vault import wizard (planv2.md §14.4)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
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
from gpg_meister.security.errors import DecryptionError
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object
from gpg_meister.security.vault_format import MAGIC
from gpg_meister.services.vault_service import VaultPreview, VaultService
from gpg_meister.ui.widgets.passphrase_field import PassphraseField
from gpg_meister.ui.worker import Worker

_PAGE_FILE = 0
_PAGE_PREVIEW = 1
_PAGE_SELECT = 2
_PAGE_RESULT = 3


class _FilePage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Select vault file")
        self.setSubTitle("Choose the .gpgm vault file to import from.")
        self._valid_vault = False
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
        self._valid_vault = False
        p = Path(text)
        if not p.exists():
            self._info_label.setText("")
            self._info_label.setStyleSheet("")
            self.completeChanged.emit()
            return

        if p.is_dir():
            self._info_label.setText("Please select a vault file, not a directory.")
            self._info_label.setStyleSheet("color: #cc0000;")
            self.completeChanged.emit()
            return

        try:
            with p.open("rb") as fh:
                data = fh.read(len(MAGIC))
            if data != MAGIC:
                if p.suffix.lower() == ".sha256":
                    self._info_label.setText(
                        "This is a checksum file (.sha256). Please select the main vault file (.gpgm)."
                    )
                else:
                    self._info_label.setText("This does not appear to be a valid GPG Meister vault file.")
                self._info_label.setStyleSheet("color: #cc0000;")
            else:
                size_kb = p.stat().st_size // 1024
                self._info_label.setText(f"Valid vault format detected.  Size: {size_kb} KB")
                self._info_label.setStyleSheet("color: #006600;")
                self._valid_vault = True
        except OSError:
            # Do not echo the raw OSError (it embeds the full path) into the UI.
            self._info_label.setText("Cannot read the selected file. Check that it exists and is readable.")
            self._info_label.setStyleSheet("color: #cc0000;")
        self.completeChanged.emit()

    def isComplete(self) -> bool:
        return self._valid_vault


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
        self._validated = False
        self._working = False

        layout = QVBoxLayout(self)
        self._pp_field = PassphraseField(show_strength=False)
        self._pp_field.setPlaceholderText("Vault master passphrase…")
        layout.addWidget(QLabel("Master passphrase:"))
        layout.addWidget(self._pp_field)

        self._status_label = QLabel()
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)
        layout.addStretch()

    def initializePage(self) -> None:
        self._validated = False
        self._working = False
        self._preview = None

    def preview(self) -> VaultPreview | None:
        return self._preview

    def passphrase(self) -> str:
        return self._pp_field.text()

    def validatePage(self) -> bool:
        if self._validated:
            return True
        if self._working:
            return False
        vault_path = Path(self.field("vault_path"))
        pp_raw_text = self._pp_field.text().strip()
        if not pp_raw_text:
            self._status_label.setText("Passphrase is required.")
            self._status_label.setStyleSheet("color: #cc0000;")
            return False

        from gpg_meister.security.password_policy import normalise_passphrase
        pp_norm_text = normalise_passphrase(pp_raw_text)

        self._status_label.setText("Decrypting vault… (this may take a moment)")
        self._status_label.setStyleSheet("color: #666666;")
        self._set_next_enabled(False)
        self._working = True

        # Capture both forms if they differ, to support vaults created without normalization.
        pp_norm_bytes = pp_norm_text.encode("utf-8")
        pp_norm_secure = SecureBytes.from_bytes(pp_norm_bytes)
        _zero_bytes_object(pp_norm_bytes)

        pp_raw_secure = None
        if pp_norm_text != pp_raw_text:
            pp_raw_bytes = pp_raw_text.encode("utf-8")
            pp_raw_secure = SecureBytes.from_bytes(pp_raw_bytes)
            _zero_bytes_object(pp_raw_bytes)

        def _do() -> VaultPreview:
            try:
                with pp_norm_secure as pp:
                    return self._vault_svc.preview(source_path=vault_path, master_passphrase=pp)
            except DecryptionError:
                # If normalized failed, and we have a different raw form, try that.
                if pp_raw_secure is not None:
                    with pp_raw_secure as pp:
                        return self._vault_svc.preview(source_path=vault_path, master_passphrase=pp)
                raise
            finally:
                if pp_raw_secure is not None:
                    pp_raw_secure.close()

        w = Worker(_do)
        w.signals.result.connect(self._on_preview_result)
        w.signals.error.connect(self._on_preview_error)
        QThreadPool.globalInstance().start(w)
        return False

    def _on_preview_result(self, result: object) -> None:
        self._working = False
        if not isinstance(result, VaultPreview):
            self._on_preview_error("Unexpected result from preview")
            return
        self._preview = result
        self._validated = True
        self._status_label.setText("Vault decrypted successfully.")
        self._status_label.setStyleSheet("color: #006600;")
        self._set_next_enabled(True)
        self.wizard().next()

    def _on_preview_error(self, msg: str) -> None:
        self._working = False
        # VaultChecksumMismatchError surfaces as a specific message; show dialog.
        if "checksum" in msg.lower():
            self._set_next_enabled(True)
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
            if reply == QMessageBox.StandardButton.Yes:
                self._run_preview_skip_checksum()
                return
            self._status_label.setText("Import cancelled.")
            self._status_label.setStyleSheet("color: #666666;")
            return
        self._status_label.setText(msg)
        self._status_label.setStyleSheet("color: #cc0000;")
        self._set_next_enabled(True)

    def _run_preview_skip_checksum(self) -> None:
        vault_path = Path(self.field("vault_path"))
        pp_text = self._pp_field.text()
        self._set_next_enabled(False)
        self._working = True

        pp_bytes = pp_text.encode()
        pp_secure = SecureBytes.from_bytes(pp_bytes)
        _zero_bytes_object(pp_bytes)

        def _do() -> VaultPreview:
            with pp_secure as pp:
                return self._vault_svc.preview(
                    source_path=vault_path, master_passphrase=pp, skip_checksum=True
                )

        w = Worker(_do)
        w.signals.result.connect(self._on_preview_result)
        w.signals.error.connect(lambda msg: self._on_skip_checksum_error(msg))
        QThreadPool.globalInstance().start(w)

    def _on_skip_checksum_error(self, msg: str) -> None:
        self._working = False
        self._status_label.setText(msg)
        self._status_label.setStyleSheet("color: #cc0000;")
        self._set_next_enabled(True)

    def _set_next_enabled(self, enabled: bool) -> None:
        wiz = self.wizard()
        if wiz is not None:
            btn = wiz.button(QWizard.WizardButton.NextButton)
            if btn is not None:
                btn.setEnabled(enabled)


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

        pp_raw_text = pp_page.passphrase().strip()
        from gpg_meister.security.password_policy import normalise_passphrase
        pp_norm_text = normalise_passphrase(pp_raw_text)

        # Capture both forms if they differ.
        pp_norm_bytes = pp_norm_text.encode("utf-8")
        pp_norm_secure = SecureBytes.from_bytes(pp_norm_bytes)
        _zero_bytes_object(pp_norm_bytes)

        pp_raw_secure = None
        if pp_norm_text != pp_raw_text:
            pp_raw_bytes = pp_raw_text.encode("utf-8")
            pp_raw_secure = SecureBytes.from_bytes(pp_raw_bytes)
            _zero_bytes_object(pp_raw_bytes)

        self._log.setPlainText("Importing keys…")
        self._set_finish_enabled(False)

        def _do() -> list[str]:
            try:
                with pp_norm_secure as pp:
                    return self._vault_svc.import_keys(
                        source_path=vault_path,
                        master_passphrase=pp,
                        fingerprints=fps,
                    )
            except DecryptionError:
                if pp_raw_secure is not None:
                    with pp_raw_secure as pp:
                        return self._vault_svc.import_keys(
                            source_path=vault_path,
                            master_passphrase=pp,
                            fingerprints=fps,
                        )
                raise
            finally:
                if pp_raw_secure is not None:
                    pp_raw_secure.close()

        w = Worker(_do)
        w.signals.result.connect(self._on_import_done)
        w.signals.error.connect(self._on_import_error)
        w.signals.finished.connect(lambda: pp_page._pp_field.clear())
        w.signals.finished.connect(lambda: self._set_finish_enabled(True))
        QThreadPool.globalInstance().start(w)

    def _on_import_done(self, result: object) -> None:
        if not isinstance(result, list):
            self._log.setPlainText("Import failed: unexpected result.")
            return
        self._imported = result
        lines = [f"Successfully imported {len(result)} key(s):\n"]
        for fp in result:
            lines.append(f"  • {fp}")
        self._log.setPlainText("\n".join(lines))

    def _on_import_error(self, msg: str) -> None:
        self._log.setPlainText(f"Import failed: {msg}")

    def _set_finish_enabled(self, enabled: bool) -> None:
        wiz = self.wizard()
        if wiz is not None:
            btn = wiz.button(QWizard.WizardButton.FinishButton)
            if btn is not None:
                btn.setEnabled(enabled)

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
