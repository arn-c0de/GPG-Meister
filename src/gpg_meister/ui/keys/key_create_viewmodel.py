"""ViewModel for key creation (planv2.md §4.8)."""

from __future__ import annotations

from PySide6.QtCore import QObject, QThreadPool, Signal

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo
from gpg_meister.security.password_policy import assess
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object
from gpg_meister.services.key_service import KeyService
from gpg_meister.ui.worker import Worker


class KeyCreateViewModel(QObject):
    """Manages form state and calls KeyService.create() in a background thread.

    Signals
    -------
    operation_succeeded   Carries the newly-created KeyInfo.
    operation_failed      Human-readable error string.
    loading_changed       True while the key-generation worker is running.
    passphrase_strength   Emitted on each passphrase edit with a string label.
    form_valid_changed    True when all fields are valid enough to submit.
    """

    operation_succeeded: Signal = Signal(object)
    operation_failed: Signal = Signal(str)
    loading_changed: Signal = Signal(bool)
    passphrase_strength: Signal = Signal(str)
    form_valid_changed: Signal = Signal(bool)

    def __init__(self, key_service: KeyService, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._svc = key_service
        self._pool = QThreadPool.globalInstance()

        self.name = ""
        self.email = ""
        self.label = ""
        self.platform = ""
        self.purpose = ""
        self.notes = ""
        self.algorithm: KeyAlgorithm = KeyAlgorithm.EDDSA
        self.length: int = 255
        self.expiry: str = "2y"
        self._passphrase = ""
        self._confirm = ""

    def set_name(self, value: str) -> None:
        self.name = value.strip()
        self._emit_validity()

    def set_email(self, value: str) -> None:
        self.email = value.strip()
        self._emit_validity()

    def set_label(self, value: str) -> None:
        self.label = value.strip()

    def set_platform(self, value: str) -> None:
        self.platform = value.strip()

    def set_purpose(self, value: str) -> None:
        self.purpose = value.strip()

    def set_notes(self, value: str) -> None:
        self.notes = value.strip()

    def set_algorithm(self, algo: KeyAlgorithm, length: int) -> None:
        self.algorithm = algo
        self.length = length
        self._emit_validity()

    def set_expiry(self, value: str) -> None:
        self.expiry = value.strip()
        self._emit_validity()

    def set_passphrase(self, value: str) -> None:
        self._passphrase = value
        result = assess(value) if value else None
        self.passphrase_strength.emit(result.strength.value if result else "")
        self._emit_validity()

    def set_confirm(self, value: str) -> None:
        self._confirm = value
        self._emit_validity()

    def _is_valid(self) -> bool:
        if not self.name or not self.email:
            return False
        if not self._passphrase:
            return False
        if self._passphrase != self._confirm:
            return False
        result = assess(self._passphrase)
        return result.accepted

    def _emit_validity(self) -> None:
        self.form_valid_changed.emit(self._is_valid())

    def submit(self) -> None:
        if not self._is_valid():
            return
        self.loading_changed.emit(True)
        # Convert to SecureBytes and drop plain-string references immediately so
        # neither the str nor the intermediate bytes object is captured by the closure.
        pp_raw = self._passphrase.encode()
        self._passphrase = ""
        self._confirm = ""
        pp_secure = SecureBytes.from_bytes(pp_raw)
        _zero_bytes_object(pp_raw)

        def _do() -> KeyInfo:
            with pp_secure as pp:
                return self._svc.create(
                    name=self.name,
                    email=self.email,
                    algorithm=self.algorithm,
                    length=self.length,
                    expiry=self.expiry,
                    passphrase=pp,
                    label=self.label,
                    platform=self.platform,
                    purpose=self.purpose,
                    notes=self.notes,
                )

        w = Worker(_do)
        w.signals.result.connect(self._on_success)
        w.signals.error.connect(self._on_error)
        w.signals.finished.connect(self._on_finished)
        self._pool.start(w)

    def _on_success(self, key: object) -> None:
        if isinstance(key, KeyInfo):
            self.operation_succeeded.emit(key)

    def _on_error(self, msg: str) -> None:
        self.operation_failed.emit(msg)

    def _on_finished(self) -> None:
        self.loading_changed.emit(False)
