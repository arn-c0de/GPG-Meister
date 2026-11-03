"""Messages tab — sub-tabs Encrypt / Decrypt / Sign / Verify / Folders / Share Key."""

from __future__ import annotations

from PySide6.QtWidgets import QTabWidget, QWidget

from gpg_meister.services.key_service import KeyService
from gpg_meister.services.key_unlock_service import KeyUnlockService
from gpg_meister.ui.messages.decrypt_view import DecryptView
from gpg_meister.ui.messages.decrypt_viewmodel import DecryptViewModel
from gpg_meister.ui.messages.encrypt_view import EncryptView
from gpg_meister.ui.messages.encrypt_viewmodel import EncryptViewModel
from gpg_meister.ui.messages.folder_view import FolderView
from gpg_meister.ui.messages.folder_viewmodel import FolderViewModel
from gpg_meister.ui.messages.share_key_view import ShareKeyView
from gpg_meister.ui.messages.sign_view import SignView
from gpg_meister.ui.messages.sign_viewmodel import SignViewModel
from gpg_meister.ui.messages.verify_view import VerifyView
from gpg_meister.ui.messages.verify_viewmodel import VerifyViewModel


class MessagesTabView(QTabWidget):
    """Top-level Messages tab containing Encrypt / Decrypt / Sign / Verify / Folders / Share Key."""

    def __init__(
        self,
        encrypt_vm: EncryptViewModel,
        decrypt_vm: DecryptViewModel,
        sign_vm: SignViewModel,
        verify_vm: VerifyViewModel,
        key_svc: KeyService,
        folder_vm: FolderViewModel | None = None,
        clipboard_clear_seconds: int = 60,
        unlock: KeyUnlockService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setDocumentMode(True)
        self.addTab(EncryptView(encrypt_vm, clipboard_clear_seconds=clipboard_clear_seconds), "Encrypt")
        self.addTab(
            DecryptView(
                decrypt_vm,
                clipboard_clear_seconds=clipboard_clear_seconds,
                unlock=unlock,
                key_service=key_svc,
            ),
            "Decrypt",
        )
        self.addTab(SignView(sign_vm), "Sign")
        self.addTab(VerifyView(verify_vm), "Verify")
        self._folder_vm = folder_vm
        if folder_vm is not None:
            self.addTab(FolderView(folder_vm), "Folders")
        self._share_key_view = ShareKeyView(key_svc)
        self.addTab(self._share_key_view, "Share Key")

    def refresh_keys(self) -> None:
        """Reload the key lists of the Share Key and Folders tabs."""
        self._share_key_view.load_keys()
        if self._folder_vm is not None:
            self._folder_vm.load_keys()
