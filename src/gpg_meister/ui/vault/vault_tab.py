"""Vault tab — Export and Import sub-tabs."""

from __future__ import annotations

from PySide6.QtWidgets import QTabWidget, QWidget

from gpg_meister.services.vault_service import VaultService
from gpg_meister.ui.vault.vault_export_view import VaultExportView
from gpg_meister.ui.vault.vault_export_viewmodel import VaultExportViewModel
from gpg_meister.ui.vault.vault_import_view import VaultImportWizard


class _ImportLaunchWidget(QWidget):
    """Simple wrapper that launches the import wizard on demand."""

    def __init__(
        self, vault_svc: VaultService, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        lbl = QLabel(
            "Import keys from a .gpgm vault file.\n\n"
            "The import wizard will guide you through:\n"
            "  1. Selecting the vault file\n"
            "  2. Entering the master passphrase\n"
            "  3. Selecting which keys to restore\n"
            "  4. Reviewing the import report"
        )
        lbl.setWordWrap(True)
        self._result_label = QLabel()
        self._result_label.setWordWrap(True)
        self._result_label.hide()
        btn = QPushButton("Open Import Wizard…")
        btn.clicked.connect(lambda: self._launch(vault_svc))
        layout.addWidget(lbl)
        layout.addWidget(btn)
        layout.addWidget(self._result_label)
        layout.addStretch()

    def _launch(self, vault_svc: VaultService) -> None:
        wizard = VaultImportWizard(vault_svc, parent=self)
        if wizard.exec() == VaultImportWizard.DialogCode.Accepted:
            fps = wizard.imported_fingerprints()
            if fps:
                self._result_label.setText(
                    f"Imported {len(fps)} key(s). Refresh the Keys tab to see them."
                )
                self._result_label.setStyleSheet("color: #006600;")
                self._result_label.show()


class VaultTabView(QTabWidget):
    """Top-level Vault tab with Export and Import sub-tabs."""

    def __init__(
        self,
        export_vm: VaultExportViewModel,
        vault_svc: VaultService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setDocumentMode(True)
        self.addTab(VaultExportView(export_vm), "Export")
        self.addTab(_ImportLaunchWidget(vault_svc), "Import")
