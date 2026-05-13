"""ViewModel for message decryption (planv2.md §4.8)."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QThreadPool, Signal

from gpg_meister.models.message import DecryptResult
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.message_service import MessageService
from gpg_meister.ui.worker import Worker


class DecryptViewModel(QObject):
    """Manages decrypt-tab state.

    Signals
    -------
    operation_succeeded   Carries the DecryptResult after successful decryption.
    operation_failed      Human-readable error string.
    loading_changed       True while the background worker is running.
    """

    operation_succeeded: Signal = Signal(object)
    operation_failed: Signal = Signal(str)
    loading_changed: Signal = Signal(bool)

    def __init__(
        self,
        message_service: MessageService,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._svc = message_service
        self._pool = QThreadPool.globalInstance()
        self._ciphertext = ""
        self._passphrase_non_empty: bool = False

    def set_ciphertext(self, text: str) -> None:
        self._ciphertext = text

    def set_passphrase_non_empty(self, non_empty: bool) -> None:
        self._passphrase_non_empty = non_empty

    def can_submit(self) -> bool:
        return bool(self._ciphertext.strip()) and self._passphrase_non_empty

    def submit(self, get_passphrase: Callable[[], str]) -> None:
        if not self.can_submit():
            return
        self.loading_changed.emit(True)
        ciphertext_bytes = self._ciphertext.encode()
        pp_str = get_passphrase()
        pp_bytes = pp_str.encode()

        def _do() -> DecryptResult:
            with SecureBytes.from_bytes(pp_bytes) as pp:
                return self._svc.decrypt(ciphertext_bytes, passphrase=pp)

        w = Worker(_do)
        w.signals.result.connect(self._on_success)
        w.signals.error.connect(self._on_error)
        w.signals.finished.connect(self._on_finished)
        self._pool.start(w)

    def _on_success(self, result: object) -> None:
        if isinstance(result, DecryptResult):
            self.operation_succeeded.emit(result)

    def _on_error(self, msg: str) -> None:
        self.operation_failed.emit(msg)

    def _on_finished(self) -> None:
        self.loading_changed.emit(False)
