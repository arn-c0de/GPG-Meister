"""First-launch keyring import wizard (planv2.md §13.1, §10 item 29).

Scans the user's system ~/.gnupg keyring (read-only) and offers to copy selected
keys into the application's dedicated keyring. Never deletes from ~/.gnupg.
"""

from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
)

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.services.gpg_service import GPGService, GPGServiceConfig
from gpg_meister.services.key_service import KeyService

_log = logging.getLogger(__name__)

_SYSTEM_GNUPG = Path.home() / ".gnupg"

_PAGE_WELCOME = 0
_PAGE_SELECT = 1
_PAGE_CONFIRM = 2


class _WelcomePage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Import keys from your system keyring")
        layout = QVBoxLayout(self)
        layout.addWidget(
            QLabel(
                "GPG Meister uses its own isolated keyring. Your personal ~/.gnupg/ "
                "is not affected.\n\n"
                "This wizard will scan your system keyring and let you copy selected "
                "keys into the application keyring.\n\n"
                "Click Next to scan ~/.gnupg/ (read-only)."
            )
        )


class _SelectPage(QWizardPage):
    def __init__(self, gpg_binary: Path) -> None:
        super().__init__()
        self.setTitle("Select keys to import")
        self._binary = gpg_binary
        self._keys: list[KeyInfo] = []

        layout = QVBoxLayout(self)
        self._status = QLabel("Scanning system keyring…")
        layout.addWidget(self._status)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["User ID", "Algorithm", "Fingerprint", "Import scope"])
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setMinimumSectionSize(80)
        layout.addWidget(self._table, stretch=1)

        self._note = QLabel(
            "Note: This wizard copies public keys only. "
            "To import a private key, use the main Import dialog."
        )
        self._note.setWordWrap(True)
        layout.addWidget(self._note)

    def initializePage(self) -> None:
        if not _SYSTEM_GNUPG.exists():
            self._status.setText("No ~/.gnupg directory found on this system.")
            return
        try:
            svc = GPGService(
                GPGServiceConfig(binary_path=self._binary, home_dir=_SYSTEM_GNUPG)
            )
            self._keys = svc.list_keys(secret=False)
        except Exception as exc:
            self._status.setText(f"Could not scan system keyring: {exc}")
            return

        self._status.setText(f"Found {len(self._keys)} key(s). Select those you want to import:")
        self._table.setRowCount(len(self._keys))
        for row, key in enumerate(self._keys):
            uid = key.user_ids[0] if key.user_ids else "—"
            self._table.setItem(row, 0, _cell(uid))
            self._table.setItem(row, 1, _cell(key.algorithm.value))
            self._table.setItem(row, 2, _cell(key.fingerprint[-16:]))
            scope = "public only (private: import manually)" if key.has_private_key else "public"
            self._table.setItem(row, 3, _cell(scope))

    def selected_keys(self) -> list[KeyInfo]:
        rows = {idx.row() for idx in self._table.selectedIndexes()}
        return [self._keys[r] for r in sorted(rows) if r < len(self._keys)]


class _ConfirmPage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Ready to import")
        self._layout = QVBoxLayout(self)
        self._summary = QLabel("The following keys will be imported:")
        self._layout.addWidget(self._summary)
        self._detail = QLabel()
        self._detail.setTextFormat(Qt.TextFormat.PlainText)
        self._detail.setWordWrap(True)
        self._layout.addWidget(self._detail)

    def set_selected(self, keys: list[KeyInfo]) -> None:
        if not keys:
            self._detail.setText("No keys selected — nothing will be imported.")
            return
        lines = []
        has_private = False
        for key in keys:
            uid = key.user_ids[0] if key.user_ids else "—"
            scope = " [PUBLIC KEY ONLY — private key not imported]" if key.has_private_key else ""
            lines.append(f"• {uid}  ({key.fingerprint[-16:]}){scope}")
            if key.has_private_key:
                has_private = True
        if has_private:
            lines.append(
                "\nPrivate key material cannot be transferred by this wizard. "
                "Use the main Import dialog to import private keys."
            )
        self._detail.setText("\n".join(lines))


class FirstLaunchWizard(QWizard):
    """Guides the user through importing system GPG keys on first launch."""

    def __init__(
        self,
        gpg_binary: Path,
        target_key_service: KeyService,
        parent: QWidget | None = None,
        *,
        trusted_sha256: str | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Import from system keyring")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setMinimumSize(600, 400)

        self._key_svc = target_key_service
        self._trusted_sha256 = trusted_sha256
        self._select_page = _SelectPage(gpg_binary)
        self._confirm_page = _ConfirmPage()

        self.addPage(_WelcomePage())
        self.addPage(self._select_page)
        self.addPage(self._confirm_page)

        self.currentIdChanged.connect(self._on_page_changed)
        self.accepted.connect(self._do_import)

    def _on_page_changed(self, page_id: int) -> None:
        if page_id == _PAGE_CONFIRM:
            self._confirm_page.set_selected(self._select_page.selected_keys())

    def _do_import(self) -> None:
        keys = self._select_page.selected_keys()
        if not keys:
            return

        try:
            system_svc = GPGService(
                GPGServiceConfig(
                    binary_path=self._select_page._binary,
                    home_dir=_SYSTEM_GNUPG,
                    trusted_sha256=self._trusted_sha256,
                )
            )
            for key in keys:
                armored = system_svc.export_public_key(key.fingerprint)
                self._key_svc.import_armored(armored)
        except Exception as exc:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.critical(
                self,
                "Import Failed",
                f"Key import failed: {exc}\n\nNo keys were imported.",
            )


def _cell(text: str) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item
