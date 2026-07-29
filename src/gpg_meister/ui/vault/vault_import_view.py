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
    QRadioButton,
    QTableWidget,
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
from gpg_meister.ui.qt_helpers import read_only_cell
from gpg_meister.ui.widgets.passphrase_field import PassphraseField
from gpg_meister.ui.worker import Worker

_PAGE_FILE = 0
_PAGE_PREVIEW = 1
_PAGE_SELECT = 2
_PAGE_RESULT = 3


def _secure_from_text(raw: str) -> SecureBytes:
    """Move a credential into a wiped-on-close buffer, verbatim.

    Card PINs go through this rather than ``_make_passphrase_pair``: the card
    compares the bytes it was programmed with, so Unicode normalisation would
    only risk turning a correct PIN into a failed attempt against a counter that
    locks the token after three tries.
    """
    raw_bytes = raw.encode("utf-8")
    secure = SecureBytes.from_bytes(raw_bytes)
    _zero_bytes_object(raw_bytes)
    return secure


def _make_passphrase_pair(raw: str) -> tuple[SecureBytes, SecureBytes | None]:
    """Return (normalised_secure, raw_secure_or_None) for vault operations.

    raw_secure is only returned when the normalised form differs from raw,
    so callers can fall back to the pre-normalisation form for legacy vaults.
    """
    from gpg_meister.security.password_policy import normalise_passphrase
    norm = normalise_passphrase(raw)
    norm_bytes = norm.encode("utf-8")
    norm_secure = SecureBytes.from_bytes(norm_bytes)
    _zero_bytes_object(norm_bytes)
    raw_secure: SecureBytes | None = None
    if norm != raw:
        raw_bytes = raw.encode("utf-8")
        raw_secure = SecureBytes.from_bytes(raw_bytes)
        _zero_bytes_object(raw_bytes)
    return norm_secure, raw_secure


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
        self.setTitle("Unlock vault")
        self.setSubTitle(
            "Enter the master passphrase for this vault. "
            "The vault will be decrypted to preview its contents."
        )
        self._vault_svc = vault_svc
        self._preview: VaultPreview | None = None
        self._validated = False
        self._working = False
        # Whether this vault advertises a token slot. Tracked as state rather
        # than read back from widget visibility: the result page asks for the
        # unlock method after the wizard has moved on, at which point every
        # widget on this page reports itself hidden.
        self._card_available = False

        layout = QVBoxLayout(self)

        # Shown only for vaults that were created with a token slot.
        self._mode_box = QWidget()
        mode_layout = QVBoxLayout(self._mode_box)
        mode_layout.setContentsMargins(0, 0, 0, 0)
        self._mode_hint = QLabel()
        self._mode_hint.setWordWrap(True)
        self._mode_hint.setStyleSheet("color: #006600;")
        mode_layout.addWidget(self._mode_hint)
        self._mode_passphrase = QRadioButton("Master passphrase")
        self._mode_passphrase.setChecked(True)
        self._mode_card = QRadioButton("Smartcard PIN")
        mode_layout.addWidget(self._mode_passphrase)
        mode_layout.addWidget(self._mode_card)
        self._mode_box.hide()
        layout.addWidget(self._mode_box)

        self._pp_label = QLabel("Master passphrase:")
        self._pp_field = PassphraseField(show_strength=False)
        self._pp_field.setPlaceholderText("Vault master passphrase…")
        layout.addWidget(self._pp_label)
        layout.addWidget(self._pp_field)

        self._status_label = QLabel()
        self._status_label.setWordWrap(True)
        layout.addWidget(self._status_label)
        layout.addStretch()

        self._mode_passphrase.toggled.connect(lambda _on: self._on_mode_changed())
        self._mode_card.toggled.connect(lambda _on: self._on_mode_changed())

    def initializePage(self) -> None:
        self._validated = False
        self._working = False
        self._preview = None
        self._show_unlock_methods()

    def _show_unlock_methods(self) -> None:
        """Offer the token as an unlock method when the vault advertises one.

        Only the vault header is read here — no credential is needed to learn
        which methods a file supports.
        """
        self._mode_box.hide()
        self._card_available = False
        self._mode_passphrase.setChecked(True)
        try:
            info = self._vault_svc.unlock_info(Path(self.field("vault_path")))
        except Exception:
            # An unreadable or malformed header is reported by the unlock
            # attempt itself; here it just means "offer the default".
            return
        if not info.accepts_smartcard:
            return
        devices = ", ".join(slot.label or slot.fingerprint[-16:] for slot in info.smartcard_slots)
        self._mode_hint.setText(f"This vault can also be opened with: {devices}")
        self._mode_passphrase.setEnabled(info.accepts_passphrase)
        self._card_available = True
        self._mode_card.setChecked(not info.accepts_passphrase)
        self._mode_box.show()
        self._on_mode_changed()

    def _on_mode_changed(self) -> None:
        if self.uses_smartcard():
            self._pp_label.setText("Smartcard PIN:")
            self._pp_field.setPlaceholderText("PIN of the token that unlocks this vault…")
        else:
            self._pp_label.setText("Master passphrase:")
            self._pp_field.setPlaceholderText("Vault master passphrase…")

    def uses_smartcard(self) -> bool:
        return self._card_available and self._mode_card.isChecked()

    def preview(self) -> VaultPreview | None:
        return self._preview

    def passphrase(self) -> str:
        return self._pp_field.text()

    def clear_passphrase(self) -> None:
        self._pp_field.clear()

    def validatePage(self) -> bool:
        if self._validated:
            return True
        if self._working:
            return False
        vault_path = Path(self.field("vault_path"))
        pp_raw_text = self._pp_field.text().strip()
        if not pp_raw_text:
            self._status_label.setText(
                "PIN is required." if self.uses_smartcard() else "Passphrase is required."
            )
            self._status_label.setStyleSheet("color: #cc0000;")
            return False

        self._status_label.setText("Decrypting vault… (this may take a moment)")
        self._status_label.setStyleSheet("color: #666666;")
        self._set_next_enabled(False)
        self._working = True

        if self.uses_smartcard():
            self._start_card_preview(vault_path, pp_raw_text)
            return False

        pp_norm_secure, pp_raw_secure = _make_passphrase_pair(pp_raw_text)

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

    def _start_card_preview(self, vault_path: Path, pin_text: str) -> None:
        """Open the vault through its token slot instead of the passphrase slot."""
        pin_secure = _secure_from_text(pin_text)

        def _do() -> VaultPreview:
            with pin_secure as pin:
                return self._vault_svc.preview(source_path=vault_path, smartcard_pin=pin)

        w = Worker(_do)
        w.signals.result.connect(self._on_preview_result)
        w.signals.error.connect(self._on_preview_error)
        QThreadPool.globalInstance().start(w)

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
        pp_text = self._pp_field.text().strip()
        self._set_next_enabled(False)
        self._working = True

        if self.uses_smartcard():
            pin_secure = _secure_from_text(pp_text)

            def _do_card() -> VaultPreview:
                with pin_secure as pin:
                    return self._vault_svc.preview(
                        source_path=vault_path, smartcard_pin=pin, skip_checksum=True
                    )

            card_worker = Worker(_do_card)
            card_worker.signals.result.connect(self._on_preview_result)
            card_worker.signals.error.connect(self._on_skip_checksum_error)
            QThreadPool.globalInstance().start(card_worker)
            return

        pp_secure, _raw_fallback = _make_passphrase_pair(pp_text)
        if _raw_fallback is not None:
            _raw_fallback.close()

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
            exp = entry.expires_at.strftime("%Y-%m-%d") if entry.expires_at else "no expiry"
            self._table.setItem(row, 0, read_only_cell(entry.primary_user_id))
            self._table.setItem(row, 1, read_only_cell(entry.fingerprint[-16:]))
            self._table.setItem(row, 2, read_only_cell("yes" if entry.has_private_key else ""))
            self._table.setItem(row, 3, read_only_cell(exp))
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
        uses_card = pp_page.uses_smartcard()
        pp_norm_secure, pp_raw_secure = _make_passphrase_pair(pp_raw_text)
        pin_secure = _secure_from_text(pp_raw_text) if uses_card else None
        # The passphrase is now held in SecureBytes; clear the input field
        # immediately rather than from a worker callback, which could fire
        # after the wizard (and the field) has been destroyed.
        pp_page.clear_passphrase()

        self._log.setPlainText("Importing keys…")
        self._set_finish_enabled(False)

        def _do_with_card() -> list[str]:
            assert pin_secure is not None
            pp_norm_secure.close()
            if pp_raw_secure is not None:
                pp_raw_secure.close()
            with pin_secure as pin:
                return self._vault_svc.import_keys(
                    source_path=vault_path,
                    smartcard_pin=pin,
                    fingerprints=fps,
                )

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

        w = Worker(_do_with_card if uses_card else _do)
        w.signals.result.connect(self._on_import_done)
        w.signals.error.connect(self._on_import_error)
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
