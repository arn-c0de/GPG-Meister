"""ViewModel for folder encryption and decryption."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from gpg_meister.security.password_policy import assess, normalise_passphrase
from gpg_meister.services.folder_service import FolderDecryptResult, FolderService
from gpg_meister.services.key_service import KeyService
from gpg_meister.ui.operation_viewmodel import OperationViewModel, read_passphrase
from gpg_meister.ui.worker import Worker


class FolderViewModel(OperationViewModel):
    """Runs folder encryption / decryption in the background.

    ``operation_succeeded`` carries the encrypted file's ``Path`` after
    encryption and a ``FolderDecryptResult`` after decryption.
    """

    keys_loaded: Signal = Signal(list)

    def __init__(
        self,
        folder_service: FolderService,
        key_service: KeyService,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._svc = folder_service
        self._key_svc = key_service

    def load_keys(self) -> None:
        worker = Worker(self._key_svc.list_keys)
        worker.signals.result.connect(self._on_keys)
        worker.signals.error.connect(self._on_error)
        self._pool.start(worker)

    def _on_keys(self, keys: object) -> None:
        if isinstance(keys, list):
            self.keys_loaded.emit(keys)

    def encrypt(
        self,
        folder: Path,
        target: Path,
        *,
        recipient: str | None,
        trust_confirmed: bool,
        get_passphrase: Callable[[], str],
    ) -> None:
        """Encrypt to ``recipient``, or with the typed passphrase when it is None."""
        passphrase = None
        if recipient is None:
            assessment = assess(normalise_passphrase(get_passphrase().strip()))
            if not assessment.accepted:
                self.operation_failed.emit(
                    f"Passphrase rejected: {assessment.reason or 'too weak'}"
                )
                return
            passphrase = read_passphrase(get_passphrase)
        recipients = (recipient,) if recipient else ()
        self.loading_changed.emit(True)

        def _do() -> Path:
            if passphrase is None:
                return self._svc.encrypt_folder(
                    folder,
                    target,
                    recipient_fingerprints=recipients,
                    trust_confirmed=trust_confirmed,
                )
            with passphrase:
                return self._svc.encrypt_folder(folder, target, passphrase=passphrase)

        self._run(_do, expect=Path)

    def decrypt(
        self,
        source: Path,
        destination: Path,
        *,
        get_passphrase: Callable[[], str],
    ) -> None:
        """Decrypt ``source`` into ``destination``; the passphrase is optional."""
        passphrase = read_passphrase(get_passphrase)
        self.loading_changed.emit(True)

        def _do() -> FolderDecryptResult:
            if passphrase is None:
                return self._svc.decrypt_folder(source, destination)
            with passphrase:
                return self._svc.decrypt_folder(source, destination, passphrase=passphrase)

        self._run(_do, expect=FolderDecryptResult)
