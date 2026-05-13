"""Messages tab — sub-tab container for Encrypt / Decrypt / Sign / Verify."""

from __future__ import annotations

from PySide6.QtWidgets import QTabWidget, QWidget

from gpg_meister.ui.messages.decrypt_view import DecryptView
from gpg_meister.ui.messages.decrypt_viewmodel import DecryptViewModel
from gpg_meister.ui.messages.encrypt_view import EncryptView
from gpg_meister.ui.messages.encrypt_viewmodel import EncryptViewModel
from gpg_meister.ui.messages.sign_view import SignView
from gpg_meister.ui.messages.sign_viewmodel import SignViewModel
from gpg_meister.ui.messages.verify_view import VerifyView
from gpg_meister.ui.messages.verify_viewmodel import VerifyViewModel


class MessagesTabView(QTabWidget):
    """Top-level Messages tab containing Encrypt / Decrypt / Sign / Verify sub-tabs."""

    def __init__(
        self,
        encrypt_vm: EncryptViewModel,
        decrypt_vm: DecryptViewModel,
        sign_vm: SignViewModel,
        verify_vm: VerifyViewModel,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setDocumentMode(True)
        self.addTab(EncryptView(encrypt_vm), "Encrypt")
        self.addTab(DecryptView(decrypt_vm), "Decrypt")
        self.addTab(SignView(sign_vm), "Sign")
        self.addTab(VerifyView(verify_vm), "Verify")
