"""ViewModel for message signing (planv2.md §4.8)."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QThreadPool, Signal

from gpg_meister.models.message import SignResult
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.key_service import KeyService
from gpg_meister.services.message_service import MessageService
from gpg_meister.ui.worker import Worker


class SignViewModel(QObject):
    """Manages sign-tab state.

    Signals
    -------
    operation_succeeded   Carries the SignResult after successful signing.
    operation_failed      Human-readable error string.
    loading_changed       True while the background worker is running.
    keys_loaded           Available private keys for signer selection.
    """

    operation_succeeded: Signal = Signal(object)
    operation_failed: Signal = Signal(str)
    loading_changed: Signal = Signal(bool)
    keys_loaded: Signal = Signal(list)

    def __init__(
        self,
        message_service: MessageService,
        key_service: KeyService,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._svc = message_service
        self._key_svc = key_service
        self._pool = QThreadPool.globalInstance()
        self._data = ""
        self._fingerprint = ""
        self._passphrase_non_empty: bool = False
        self._detached = True

    def load_keys(self) -> None:
        def _list_private() -> list[object]:
            return [k for k in self._key_svc.list_keys() if k.has_private_key]

        w = Worker(_list_private)
        w.signals.result.connect(self._on_keys)
        w.signals.error.connect(lambda msg: self.operation_failed.emit(msg))
        self._pool.start(w)

    def _on_keys(self, keys: object) -> None:
        if isinstance(keys, list):
            self.keys_loaded.emit(keys)

    def set_data(self, text: str) -> None:
        self._data = text

    def set_fingerprint(self, fp: str) -> None:
        self._fingerprint = fp

    def set_passphrase_non_empty(self, non_empty: bool) -> None:
        self._passphrase_non_empty = non_empty

    def set_detached(self, detached: bool) -> None:
        self._detached = detached

    def can_submit(self) -> bool:
        return bool(self._data.strip()) and bool(self._fingerprint) and self._passphrase_non_empty

    def submit(self, get_passphrase: Callable[[], str]) -> None:
        if not self.can_submit():
            return
        self.loading_changed.emit(True)
        data_bytes = self._data.encode()
        fp = self._fingerprint
        pp_str = get_passphrase()
        pp_bytes = pp_str.encode()
        detached = self._detached

        def _do() -> SignResult:
            with SecureBytes.from_bytes(pp_bytes) as pp:
                return self._svc.sign(data_bytes, fingerprint=fp, passphrase=pp, detached=detached)

        w = Worker(_do)
        w.signals.result.connect(self.operation_succeeded.emit)
        w.signals.error.connect(self.operation_failed.emit)
        w.signals.finished.connect(lambda: self.loading_changed.emit(False))
        self._pool.start(w)
