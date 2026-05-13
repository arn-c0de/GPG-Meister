"""ViewModel for signature verification (planv2.md §4.8)."""

from __future__ import annotations

from PySide6.QtCore import QObject, QThreadPool, Signal

from gpg_meister.models.message import VerifyResult
from gpg_meister.services.message_service import MessageService
from gpg_meister.ui.worker import Worker


class VerifyViewModel(QObject):
    """Manages verify-tab state.

    Signals
    -------
    operation_succeeded   Carries the VerifyResult after verification.
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
        self._data = ""
        self._signature = ""

    def set_data(self, text: str) -> None:
        self._data = text

    def set_signature(self, text: str) -> None:
        self._signature = text

    def can_submit(self) -> bool:
        return bool(self._data.strip())

    def submit(self) -> None:
        if not self.can_submit():
            return
        self.loading_changed.emit(True)
        data_bytes = self._data.encode()
        sig_bytes = self._signature.encode() if self._signature.strip() else None

        def _do() -> VerifyResult:
            return self._svc.verify(data_bytes, detached_signature=sig_bytes)

        w = Worker(_do)
        w.signals.result.connect(self._on_success)
        w.signals.error.connect(self._on_error)
        w.signals.finished.connect(lambda: self.loading_changed.emit(False))
        self._pool.start(w)

    def _on_success(self, result: object) -> None:
        if isinstance(result, VerifyResult):
            self.operation_succeeded.emit(result)

    def _on_error(self, msg: str) -> None:
        self.operation_failed.emit(msg)
