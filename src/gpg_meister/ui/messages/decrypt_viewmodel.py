"""ViewModel for message decryption (planv2.md §4.8)."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QThreadPool, Signal

from gpg_meister.models.message import DecryptResult
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object
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

    def set_ciphertext(self, text: str) -> None:
        self._ciphertext = text

    def can_submit(self) -> bool:
        return bool(self._ciphertext.strip())

    def submit(self, get_passphrase: Callable[[], str]) -> None:
        if not self.can_submit():
            return
        self.loading_changed.emit(True)
        ciphertext_bytes = self._ciphertext.encode()
        pp_str = get_passphrase()
        # Convert to SecureBytes on the UI thread and drop the plain-string
        # reference immediately so it is not captured by the closure below.
        if pp_str:
            _pp_raw = pp_str.encode()
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

        w = Worker(_do, emit_result=False)
        w.signals.result_ready.connect(lambda: self._on_success(w.take_result()))
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
