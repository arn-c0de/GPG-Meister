"""ViewModel for vault export (planv2.md §4.8)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, QThreadPool, Signal

from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.key_service import KeyService
from gpg_meister.services.vault_service import VaultDescriptor, VaultService
from gpg_meister.ui.worker import Worker


class VaultExportViewModel(QObject):
    """Manages vault-export tab state.

    Signals
    -------
    operation_succeeded   Carries the VaultDescriptor after a successful export.
    operation_failed      Human-readable error string.
    loading_changed       True while the background worker is running.
    keys_loaded           Private keys available for vault inclusion.
    """

    operation_succeeded: Signal = Signal(object)
    operation_failed: Signal = Signal(str)
    loading_changed: Signal = Signal(bool)
    keys_loaded: Signal = Signal(list)

    def __init__(
        self,
        vault_service: VaultService,
        key_service: KeyService,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._vault_svc = vault_service
        self._key_svc = key_service
        self._pool = QThreadPool.globalInstance()

        self._selected_fps: list[str] = []
        self._target_path: Path | None = None
        self._master_passphrase = ""
        self._confirm_passphrase = ""
        self._gpg_passphrase = ""
        self._description = ""

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

    def set_selected(self, fingerprints: list[str]) -> None:
        self._selected_fps = fingerprints

    def set_target_path(self, path: Path | None) -> None:
        self._target_path = path

    def set_master_passphrase(self, value: str) -> None:
        self._master_passphrase = value

    def set_confirm_passphrase(self, value: str) -> None:
        self._confirm_passphrase = value

    def set_gpg_passphrase(self, value: str) -> None:
        self._gpg_passphrase = value

    def set_description(self, value: str) -> None:
        self._description = value.strip()

    def can_submit(self) -> bool:
        return (
            bool(self._selected_fps)
            and self._target_path is not None
            and bool(self._master_passphrase)
            and self._master_passphrase == self._confirm_passphrase
            and bool(self._gpg_passphrase)
        )

    def submit(self) -> None:
        if not self.can_submit() or self._target_path is None:
            return
        self.loading_changed.emit(True)
        fps = list(self._selected_fps)
        target = self._target_path
        master_bytes = self._master_passphrase.encode()
        gpg_bytes = self._gpg_passphrase.encode()
        self._master_passphrase = ""
        self._confirm_passphrase = ""
        self._gpg_passphrase = ""
        desc = self._description

        def _do() -> VaultDescriptor:
            with (
                SecureBytes.from_bytes(master_bytes) as master_pp,
                SecureBytes.from_bytes(gpg_bytes) as gpg_pp,
            ):
                return self._vault_svc.create(
                    target_path=target,
                    master_passphrase=master_pp,
                    gpg_passphrase=gpg_pp,
                    fingerprints=fps,
                    description=desc,
                )

        w = Worker(_do)
        w.signals.result.connect(self.operation_succeeded.emit)
        w.signals.error.connect(self.operation_failed.emit)
        w.signals.finished.connect(lambda: self.loading_changed.emit(False))
        self._pool.start(w)
