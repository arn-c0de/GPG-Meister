"""ViewModel for the Settings tab (planv2.md §4.8)."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from gpg_meister.models.config import AppConfig, AppearanceMode, AppPage
from gpg_meister.models.kdf_params import KDFProfile
from gpg_meister.models.vault import CipherAlgorithm
from gpg_meister.services import config_service
from gpg_meister.storage.factory_reset import request_factory_reset
from gpg_meister.storage.paths import AppPaths


class SettingsViewModel(QObject):
    """Manages editable copy of AppConfig and persists changes.

    Signals
    -------
    config_saved     Emitted after a successful save.
    save_failed      Human-readable error string.
    """

    config_saved: Signal = Signal()
    save_failed: Signal = Signal(str)
    factory_reset_scheduled: Signal = Signal()
    factory_reset_failed: Signal = Signal(str)

    def __init__(
        self,
        config: AppConfig,
        paths: AppPaths,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._path = paths.config_file
        self._paths = paths
        # Work on a mutable snapshot; original is not mutated until save().
        self._saved = config.model_copy(deep=True)
        self._pending = config.model_copy(deep=True)

    @property
    def config(self) -> AppConfig:
        return self._pending

    def set_locale(self, locale: str) -> None:
        self._pending.locale = locale

    def set_appearance(self, appearance: AppearanceMode) -> None:
        self._pending.appearance = appearance

    def persist_last_open_page(self, page: AppPage) -> None:
        saved = self._saved.model_copy(update={"last_open_page": page})
        try:
            config_service.save(saved, self._path)
        except Exception as exc:
            self.save_failed.emit(str(exc))
            return
        self._saved = saved
        self._pending.last_open_page = page

    def set_cipher(self, cipher: CipherAlgorithm) -> None:
        self._pending.cipher = cipher

    def set_kdf_profile(self, profile: KDFProfile) -> None:
        self._pending.kdf_profile = profile

    def set_clipboard_clear_seconds(self, secs: int) -> None:
        self._pending.clipboard_clear_seconds = max(0, min(3600, secs))

    def set_backup_reminder_days(self, days: int) -> None:
        self._pending.backup_reminder_days = max(1, min(365, days))

    def set_high_contrast(self, on: bool) -> None:
        self._pending.high_contrast = on

    def set_reduce_motion(self, on: bool) -> None:
        self._pending.reduce_motion = on

    def set_require_delete_text_confirmation(self, on: bool) -> None:
        self._pending.require_delete_text_confirmation = on

    def set_audit_hash_chain(self, on: bool) -> None:
        self._pending.audit = self._pending.audit.model_copy(update={"hash_chain": on})

    def save(self) -> None:
        try:
            config_service.save(self._pending, self._path)
            self._saved = self._pending.model_copy(deep=True)
            self.config_saved.emit()
        except Exception as exc:
            self.save_failed.emit(str(exc))

    def schedule_factory_reset(self) -> None:
        try:
            request_factory_reset(self._paths)
            self._pending = AppConfig()
            self.factory_reset_scheduled.emit()
        except Exception as exc:
            self.factory_reset_failed.emit(str(exc))
