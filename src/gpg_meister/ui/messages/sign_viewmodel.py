"""ViewModel for message signing (planv2.md §4.8)."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, Signal

from gpg_meister.models.message import SignResult
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object
from gpg_meister.services.key_service import KeyService
from gpg_meister.services.message_service import MessageService
from gpg_meister.ui.operation_viewmodel import OperationViewModel
from gpg_meister.ui.worker import Worker


class SignViewModel(OperationViewModel):
    """Manages sign-tab state.

    Signals
    -------
    operation_succeeded   Carries the SignResult after successful signing.
    operation_failed      Human-readable error string.
    loading_changed       True while the background worker is running.
    keys_loaded           Available private keys for signer selection.
    """

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
        self._data = ""
        self._fingerprint = ""
        self._passphrase_non_empty: bool = False
        self._detached = True

    def load_keys(self) -> None:
        def _list_private() -> list[object]:
            return [k for k in self._key_svc.list_keys() if k.has_private_key]

        w = Worker(_list_private)
        w.signals.result.connect(self._on_keys)
        w.signals.error.connect(self._on_error)
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
        pp_str = get_passphrase().strip()
        from gpg_meister.security.password_policy import normalise_passphrase
        pp_bytes = normalise_passphrase(pp_str).encode()
        del pp_str
        pp_secure = SecureBytes.from_bytes(pp_bytes)
        _zero_bytes_object(pp_bytes)
        detached = self._detached

        def _do() -> SignResult:
            with pp_secure as pp:
                return self._svc.sign(data_bytes, fingerprint=fp, passphrase=pp, detached=detached)

        self._run(_do, expect=SignResult)
