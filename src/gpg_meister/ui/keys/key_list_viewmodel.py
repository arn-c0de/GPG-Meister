"""ViewModel for the key list tab (planv2.md §4.8)."""

from __future__ import annotations

from PySide6.QtCore import QObject, QThreadPool, Signal

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.key_service import KeyService
from gpg_meister.ui.worker import Worker


class KeyListViewModel(QObject):
    """Owns the key-list state. Views bind to its signals; they never call services.

    Signals
    -------
    keys_changed        Emitted with the refreshed list after any mutation.
    loading_changed     True while a background operation is running.
    operation_failed    Human-readable error string.
    key_created         Emitted after a successful create; carries the new KeyInfo.
                        The main window listens to this to show the backup banner.
    """

    keys_changed: Signal = Signal(list)
    loading_changed: Signal = Signal(bool)
    operation_failed: Signal = Signal(str)
    key_created: Signal = Signal(object)

    def __init__(
        self,
        key_service: KeyService,
        *,
        require_delete_text_confirmation: bool = True,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._svc = key_service
        self._pool = QThreadPool.globalInstance()
        self._keys: list[KeyInfo] = []
        self._require_delete_text_confirmation = require_delete_text_confirmation

    @property
    def keys(self) -> list[KeyInfo]:
        return list(self._keys)

    def refresh(self) -> None:
        self.loading_changed.emit(True)
        w = Worker(self._svc.list_keys)
        w.signals.result.connect(self._on_keys_loaded)
        w.signals.error.connect(self._on_error)
        w.signals.finished.connect(self._on_finished)
        self._pool.start(w)

    @property
    def require_delete_text_confirmation(self) -> bool:
        return self._require_delete_text_confirmation

    def set_require_delete_text_confirmation(self, on: bool) -> None:
        self._require_delete_text_confirmation = on

    def _on_keys_loaded(self, keys: object) -> None:
        if not isinstance(keys, list):
            return
        self._keys = keys
        self.keys_changed.emit(self._keys)

    def request_delete(
        self,
        fingerprint: str,
        *,
        including_secret: bool,
        passphrase: SecureBytes | None = None,
    ) -> None:
        self.loading_changed.emit(True)

        def _do() -> str:
            self._svc.delete(
                fingerprint,
                including_secret=including_secret,
                passphrase=passphrase,
            )
            return fingerprint

        w = Worker(_do)
        w.signals.result.connect(self._on_delete_succeeded)
        w.signals.error.connect(self._on_error)
        w.signals.finished.connect(self._on_finished)
        self._pool.start(w)

    def notify_key_created(self, key: KeyInfo) -> None:
        self.key_created.emit(key)
        self.refresh()

    def _on_delete_succeeded(self, _fingerprint: object) -> None:
        self.refresh()

    def _on_finished(self) -> None:
        self.loading_changed.emit(False)

    def _on_error(self, msg: str) -> None:
        self.operation_failed.emit(msg)
