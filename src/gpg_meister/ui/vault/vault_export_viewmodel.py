"""ViewModel for vault export (planv2.md §4.8)."""

from __future__ import annotations

import contextlib
from pathlib import Path

from PySide6.QtCore import QObject, QThreadPool, Signal

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object
from gpg_meister.services.key_service import KeyService
from gpg_meister.services.vault_service import VaultDescriptor, VaultService
from gpg_meister.ui.worker import Worker


class VaultExportViewModel(QObject):
    """Manages vault-export tab state with per-key passphrase unlocking.

    Signals
    -------
    operation_succeeded     Carries the VaultDescriptor after a successful export.
    operation_failed        Human-readable error string.
    loading_changed         True while the background worker is running.
    keys_loaded             Private keys available for vault inclusion.
    key_unlock_state_changed  (fingerprint, is_unlocked) when a key is locked/unlocked.
    """

    operation_succeeded: Signal = Signal(object)
    operation_failed: Signal = Signal(str)
    loading_changed: Signal = Signal(bool)
    keys_loaded: Signal = Signal(list)
    key_unlock_state_changed: Signal = Signal(str, bool)

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
        self._description = ""

        # Per-key state: fp → plaintext passphrase (cleared before worker starts).
        self._key_passphrases: dict[str, str] = {}
        # fps that have been explicitly unlocked by the user.
        self._unlocked_fps: set[str] = set()
        # Loaded key info for stub detection (fp → KeyInfo).
        self._key_map: dict[str, KeyInfo] = {}

    # ------------------------------------------------------------------ loading

    def load_keys(self) -> None:
        def _list_private() -> list[object]:
            return [k for k in self._key_svc.list_keys() if k.has_private_key]

        w = Worker(_list_private)
        w.signals.result.connect(self._on_keys)
        w.signals.error.connect(self._on_error)
        self._pool.start(w)

    def _on_keys(self, keys: object) -> None:
        if isinstance(keys, list):
            self._key_map = {k.fingerprint: k for k in keys if isinstance(k, KeyInfo)}
            self.keys_loaded.emit(keys)

    # ---------------------------------------------------------------- selection

    def set_selected(self, fingerprints: list[str]) -> None:
        removed = set(self._selected_fps) - set(fingerprints)
        self._selected_fps = fingerprints
        # Clear stored passphrases for keys that were deselected.
        for fp in removed:
            self._key_passphrases.pop(fp, None)
            if fp in self._unlocked_fps:
                self._unlocked_fps.discard(fp)
                self.key_unlock_state_changed.emit(fp, False)
        # Auto-unlock stub keys (no passphrase needed).
        for fp in fingerprints:
            key = self._key_map.get(fp)
            if key and key.is_stub and fp not in self._unlocked_fps:
                self._unlocked_fps.add(fp)
                self.key_unlock_state_changed.emit(fp, True)

    def set_target_path(self, path: Path | None) -> None:
        self._target_path = path

    def set_master_passphrase(self, value: str) -> None:
        self._master_passphrase = value

    def set_confirm_passphrase(self, value: str) -> None:
        self._confirm_passphrase = value

    def set_description(self, value: str) -> None:
        self._description = value.strip()

    # ---------------------------------------------------------- per-key unlock

    def set_key_passphrase(self, fp: str, passphrase: str) -> None:
        """Store the candidate passphrase for a key (does not yet unlock it)."""
        self._key_passphrases[fp] = passphrase

    def unlock_key(self, fp: str) -> bool:
        """Mark a key as unlocked. Returns True if passphrase is non-empty."""
        passphrase = self._key_passphrases.get(fp, "")
        if not passphrase:
            return False
        self._unlocked_fps.add(fp)
        self.key_unlock_state_changed.emit(fp, True)
        return True

    def lock_key(self, fp: str) -> None:
        self._key_passphrases.pop(fp, None)
        if fp in self._unlocked_fps:
            self._unlocked_fps.discard(fp)
            self.key_unlock_state_changed.emit(fp, False)

    def is_key_unlocked(self, fp: str) -> bool:
        key = self._key_map.get(fp)
        if key and key.is_stub:
            return True
        return fp in self._unlocked_fps

    # ----------------------------------------------------------------- submit

    def can_submit(self) -> bool:
        if not self._selected_fps or self._target_path is None:
            return False
        if not self._master_passphrase or self._master_passphrase != self._confirm_passphrase:
            return False
        return all(self.is_key_unlocked(fp) for fp in self._selected_fps)

    def submit(self) -> None:
        if not self.can_submit() or self._target_path is None:
            return
        self.loading_changed.emit(True)

        fps = list(self._selected_fps)
        target = self._target_path
        desc = self._description

        _master_raw = self._master_passphrase.encode()
        master_secure = SecureBytes.from_bytes(_master_raw)
        _zero_bytes_object(_master_raw)
        self._master_passphrase = ""
        self._confirm_passphrase = ""

        # Capture per-key SecureBytes and wipe plaintext.
        gpg_secure: dict[str, SecureBytes] = {}
        for fp in fps:
            if fp in self._key_passphrases:
                _raw = self._key_passphrases[fp].encode()
                gpg_secure[fp] = SecureBytes.from_bytes(_raw)
                _zero_bytes_object(_raw)
        for fp in fps:
            self._key_passphrases.pop(fp, None)
        self._unlocked_fps.difference_update(fps)

        def _do() -> VaultDescriptor:
            with master_secure as master_pp:
                with contextlib.ExitStack() as stack:
                    gpg_pps: dict[str, SecureBytes] = {
                        fp: stack.enter_context(pw)
                        for fp, pw in gpg_secure.items()
                    }
                    return self._vault_svc.create(
                        target_path=target,
                        master_passphrase=master_pp,
                        gpg_passphrases=gpg_pps,
                        fingerprints=fps,
                        description=desc,
                    )

        w = Worker(_do)
        w.signals.result.connect(self._on_success)
        w.signals.error.connect(self._on_error)
        w.signals.finished.connect(self._on_finished)
        self._pool.start(w)

    def _on_success(self, result: object) -> None:
        if isinstance(result, VaultDescriptor):
            self.operation_succeeded.emit(result)

    def _on_error(self, msg: str) -> None:
        self.operation_failed.emit(msg)

    def _on_finished(self) -> None:
        self.loading_changed.emit(False)
