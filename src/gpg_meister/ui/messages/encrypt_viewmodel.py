"""ViewModel for message encryption (planv2.md §4.8, §14.2)."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject

from gpg_meister.models.message import EncryptResult
from gpg_meister.services.key_service import KeyService
from gpg_meister.services.message_service import MessageService
from gpg_meister.ui.operation_viewmodel import OperationViewModel, read_passphrase


class EncryptViewModel(OperationViewModel):
    """Manages encrypt-tab state.

    Signals
    -------
    operation_succeeded   Carries the EncryptResult after successful encryption.
    operation_failed      Human-readable error string.
    loading_changed       True while the background worker is running.
    keys_loaded           Available keys for recipient / signer selection.
    """

    def __init__(
        self,
        message_service: MessageService,
        key_service: KeyService,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._msg_svc = message_service
        self._key_svc = key_service

        self._plaintext = ""
        self._recipient_fps: list[str] = []
        self._sign_with: str | None = None
        self._trust_confirmed: bool = False

    def load_keys(self) -> None:
        self._load_keys(self._key_svc)

    def set_plaintext(self, text: str) -> None:
        self._plaintext = text

    def set_recipients(self, fingerprints: list[str]) -> None:
        self._recipient_fps = fingerprints

    def set_sign_with(self, fingerprint: str | None) -> None:
        self._sign_with = fingerprint

    def set_trust_confirmed(self, confirmed: bool) -> None:
        self._trust_confirmed = confirmed

    def can_submit(self) -> bool:
        return (
            bool(self._plaintext.strip())
            and bool(self._recipient_fps)
            and self._trust_confirmed
        )

    def submit(self, get_passphrase: Callable[[], str] | None = None) -> None:
        if not self.can_submit():
            return
        self.loading_changed.emit(True)
        plaintext_bytes = self._plaintext.encode()
        fps = list(self._recipient_fps)
        sign_with = self._sign_with
        # Read the signing passphrase once, here on the UI thread (L7).
        pp_secure = read_passphrase(get_passphrase)
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

        self._run(_do, expect=EncryptResult)
