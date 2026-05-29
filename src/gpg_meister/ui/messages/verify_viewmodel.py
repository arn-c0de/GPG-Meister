"""ViewModel for signature verification (planv2.md §4.8)."""

from __future__ import annotations

from PySide6.QtCore import QObject

from gpg_meister.models.message import VerifyResult
from gpg_meister.services.message_service import MessageService
from gpg_meister.ui.operation_viewmodel import OperationViewModel


class VerifyViewModel(OperationViewModel):
    """Manages verify-tab state.

    Signals (inherited from OperationViewModel)
    -------------------------------------------
    operation_succeeded   Carries the VerifyResult after verification.
    operation_failed      Human-readable error string.
    loading_changed       True while the background worker is running.
    """

    def __init__(
        self,
        message_service: MessageService,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._svc = message_service
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

        self._run(_do, expect=VerifyResult)
