"""ViewModel for message decryption (planv2.md §4.8)."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, Signal

from gpg_meister.models.message import DecryptResult
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object
from gpg_meister.services.message_service import MessageService
from gpg_meister.services.smartcard_service import CardSyncResult, SmartcardService
from gpg_meister.ui.operation_viewmodel import OperationViewModel
from gpg_meister.ui.worker import Worker


class DecryptViewModel(OperationViewModel):
    """Manages decrypt-tab state.

    Signals (inherited from OperationViewModel)
    -------------------------------------------
    operation_succeeded   Carries the DecryptResult after successful decryption.
    operation_failed      Human-readable error string.
    loading_changed       True while the background worker is running.
    card_changed          Latest smartcard probe, so the view can ask for a PIN
                          instead of a passphrase when a token key is involved.
    """

    card_changed: Signal = Signal(object)

    def __init__(
        self,
        message_service: MessageService,
        smartcard_service: SmartcardService | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._svc = message_service
        self._smartcard = smartcard_service
        self._ciphertext = ""

    def refresh_card(self) -> None:
        """Probe the token in the background; failures stay silent (see key list)."""
        if self._smartcard is None:
            self.card_changed.emit(None)
            return
        worker = Worker(self._smartcard.sync)
        worker.signals.result.connect(self._on_card_result)
        self._pool.start(worker)

    def _on_card_result(self, result: object) -> None:
        if isinstance(result, CardSyncResult):
            self.card_changed.emit(result)

    def set_ciphertext(self, text: str) -> None:
        self._ciphertext = text

    def can_submit(self) -> bool:
        return bool(self._ciphertext.strip())

    def submit(self, get_passphrase: Callable[[], str]) -> None:
        if not self.can_submit():
            return
        self.loading_changed.emit(True)
        ciphertext_bytes = self._ciphertext.encode()
        pp_str = get_passphrase().strip()
        # Convert to SecureBytes on the UI thread and drop the plain-string
        # reference immediately so it is not captured by the closure below.
        if pp_str:
            from gpg_meister.security.password_policy import normalise_passphrase
            _pp_raw = normalise_passphrase(pp_str).encode()
            pp_secure = SecureBytes.from_bytes(_pp_raw)
            _zero_bytes_object(_pp_raw)
        else:
            pp_secure = None
        del pp_str

        def _do() -> DecryptResult:
            if pp_secure is not None:
                with pp_secure:
                    return self._svc.decrypt(ciphertext_bytes, passphrase=pp_secure)
            return self._svc.decrypt(ciphertext_bytes, passphrase=None)

        # secure_result: pull the plaintext via take_result() so it is never
        # carried across threads inside a Qt signal payload.
        self._run(_do, expect=DecryptResult, secure_result=True)

    def submit_with_secret(self, secret: SecureBytes) -> None:
        """Decrypt with a passphrase a security key produced, not a typed one.

        Takes ownership of ``secret`` and closes it once the attempt is over —
        including when the ciphertext turns out to be unusable, so a passphrase
        recovered from a token never outlives the operation it was fetched for.
        """
        if not self.can_submit():
            secret.close()
            return
        self.loading_changed.emit(True)
        ciphertext_bytes = self._ciphertext.encode()

        def _do() -> DecryptResult:
            with secret:
                return self._svc.decrypt(ciphertext_bytes, passphrase=secret)

        self._run(_do, expect=DecryptResult, secure_result=True)
