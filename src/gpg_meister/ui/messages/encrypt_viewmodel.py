"""ViewModel for message encryption (planv2.md §4.8, §14.2)."""

from __future__ import annotations

from PySide6.QtCore import QObject, QThreadPool, Signal

from gpg_meister.models.message import EncryptResult
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object
from gpg_meister.services.key_service import KeyService
from gpg_meister.services.message_service import MessageService
from gpg_meister.ui.worker import Worker


class EncryptViewModel(QObject):
    """Manages encrypt-tab state.

    Signals
    -------
    operation_succeeded   Carries the EncryptResult after successful encryption.
    operation_failed      Human-readable error string.
    loading_changed       True while the background worker is running.
    keys_loaded           Available keys for recipient / signer selection.
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
        self._msg_svc = message_service
        self._key_svc = key_service
        self._pool = QThreadPool.globalInstance()

        self._plaintext = ""
        self._recipient_fps: list[str] = []
        self._sign_with: str | None = None
        self._passphrase = ""
        self._trust_confirmed: bool = False

    def load_keys(self) -> None:
        w = Worker(self._key_svc.list_keys)
        w.signals.result.connect(self._on_keys)
        w.signals.error.connect(self._on_error)
        self._pool.start(w)

    def _on_keys(self, keys: object) -> None:
        if isinstance(keys, list):
            self.keys_loaded.emit(keys)

    def set_plaintext(self, text: str) -> None:
        self._plaintext = text

    def set_recipients(self, fingerprints: list[str]) -> None:
        self._recipient_fps = fingerprints

    def set_sign_with(self, fingerprint: str | None) -> None:
        self._sign_with = fingerprint

    def set_passphrase(self, value: str) -> None:
        self._passphrase = value

    def set_trust_confirmed(self, confirmed: bool) -> None:
        self._trust_confirmed = confirmed

    def can_submit(self) -> bool:
        return (
            bool(self._plaintext.strip())
            and bool(self._recipient_fps)
            and self._trust_confirmed
        )

    def submit(self) -> None:
        if not self.can_submit():
            return
        self.loading_changed.emit(True)
        plaintext_bytes = self._plaintext.encode()
        fps = list(self._recipient_fps)
        sign_with = self._sign_with
        if self._passphrase:
            from gpg_meister.security.password_policy import normalise_passphrase
            _pp_raw = normalise_passphrase(self._passphrase).encode()
            pp_secure = SecureBytes.from_bytes(_pp_raw)
            _zero_bytes_object(_pp_raw)
        else:
            pp_secure = None
        self._passphrase = ""
        trust = self._trust_confirmed
        self._trust_confirmed = False

        def _do() -> EncryptResult:
            if pp_secure is not None:
                with pp_secure as pp:
                    return self._msg_svc.encrypt(
                        plaintext_bytes,
                        recipient_fingerprints=fps,
                        sign_with=sign_with,
                        passphrase=pp,
                        always_trust=trust,
                        trust_confirmed=trust,
                    )
            return self._msg_svc.encrypt(
                plaintext_bytes,
                recipient_fingerprints=fps,
                sign_with=sign_with,
                always_trust=trust,
                trust_confirmed=trust,
            )

        w = Worker(_do)
        w.signals.result.connect(self._on_success)
        w.signals.error.connect(self._on_error)
        w.signals.finished.connect(self._on_finished)
        self._pool.start(w)

    def _on_success(self, result: object) -> None:
        if isinstance(result, EncryptResult):
            self.operation_succeeded.emit(result)

    def _on_error(self, msg: str) -> None:
        self.operation_failed.emit(msg)

    def _on_finished(self) -> None:
        self.loading_changed.emit(False)
