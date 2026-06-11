"""Settings tab view (planv2.md §4.8)."""

from __future__ import annotations

from enum import StrEnum
from typing import TypeVar

from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.i18n import available_language_options
from gpg_meister.models.config import AppearanceMode
from gpg_meister.models.kdf_params import KDFProfile
from gpg_meister.models.vault import CipherAlgorithm
from gpg_meister.ui.settings.settings_viewmodel import SettingsViewModel

_EnumT = TypeVar("_EnumT", bound=StrEnum)


class SettingsView(QWidget):
    """Settings form: locale, cipher, KDF, clipboard, backup reminder, flags."""

    _FACTORY_RESET_CONFIRM_TEXT = "RESET"

    def __init__(self, viewmodel: SettingsViewModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vm = viewmodel
        self._build_ui()
        self._connect_signals()
        self._load_current()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)
        root.addWidget(self._build_language_box())
        root.addWidget(self._build_crypto_box())
        root.addWidget(self._build_interface_box())
        root.addWidget(self._build_audit_box())
        root.addWidget(self._build_deletion_box())
        root.addWidget(self._build_reset_box())
        root.addLayout(self._build_button_row())
        root.addStretch()

    def _build_language_box(self) -> QGroupBox:
        box = QGroupBox("Language")
        form = QFormLayout(box)
        self._locale_combo = QComboBox()
        for language in available_language_options():
            self._locale_combo.addItem(language.label, language.code)
        self._locale_combo.setAccessibleName("Language")
        form.addRow("Language:", self._locale_combo)
        form.addRow("", QLabel("Language change takes effect on next launch."))
        return box

    def _build_crypto_box(self) -> QGroupBox:
        box = QGroupBox("Cryptography")
        form = QFormLayout(box)

        self._cipher_combo = QComboBox()
        self._cipher_combo.addItem(
            "ChaCha20-Poly1305 (recommended)",
            CipherAlgorithm.CHACHA20_POLY1305.value,
        )
        self._cipher_combo.addItem("AES-256-GCM", CipherAlgorithm.AES_256_GCM.value)
        self._cipher_combo.setAccessibleName("Vault cipher algorithm")
        form.addRow("Vault cipher:", self._cipher_combo)

        self._kdf_combo = QComboBox()
        self._kdf_combo.addItem("High memory (safer, ~1 s)", KDFProfile.HIGH_MEMORY.value)
        self._kdf_combo.addItem("Balanced (faster, ~0.2 s)", KDFProfile.BALANCED.value)
        self._kdf_combo.setAccessibleName("KDF profile")
        form.addRow("KDF profile:", self._kdf_combo)
        return box

    def _build_interface_box(self) -> QGroupBox:
        box = QGroupBox("Interface")
        form = QFormLayout(box)

        self._clipboard_spin = QSpinBox()
        self._clipboard_spin.setRange(0, 3600)
        self._clipboard_spin.setSuffix(" seconds")
        self._clipboard_spin.setSpecialValueText("Never clear")
        self._clipboard_spin.setAccessibleName("Clipboard auto-clear delay")
        form.addRow("Clear clipboard after:", self._clipboard_spin)

        self._appearance_combo = QComboBox()
        self._appearance_combo.addItem("Dark mode", AppearanceMode.SYSTEM.value)
        self._appearance_combo.addItem("Day mode", AppearanceMode.LIGHT.value)
        self._appearance_combo.setAccessibleName("Appearance")
        form.addRow("Color mode:", self._appearance_combo)

        self._backup_spin = QSpinBox()
        self._backup_spin.setRange(1, 365)
        self._backup_spin.setSuffix(" days")
        self._backup_spin.setAccessibleName("Backup reminder interval")
        form.addRow("Vault backup reminder every:", self._backup_spin)

        self._high_contrast_check = QCheckBox("Enable high-contrast theme")
        self._high_contrast_check.setAccessibleDescription(
            "Increases foreground/background contrast ratio"
        )
        form.addRow("", self._high_contrast_check)

        self._reduce_motion_check = QCheckBox("Reduce animations")
        self._reduce_motion_check.setAccessibleDescription(
            "Disables or reduces animated transitions"
        )
        form.addRow("", self._reduce_motion_check)
        return box

    def _build_audit_box(self) -> QGroupBox:
        box = QGroupBox("Audit log")
        form = QFormLayout(box)
        self._hash_chain_check = QCheckBox("Enable hash-chain integrity (append-only proof)")
        self._hash_chain_check.setAccessibleDescription(
            "Each audit record includes a hash of the previous record, "
            "making it detectable if records are deleted or reordered."
        )
        form.addRow("", self._hash_chain_check)
        return box

    def _build_deletion_box(self) -> QGroupBox:
        box = QGroupBox("Deletion safety")
        form = QFormLayout(box)
        self._delete_text_confirmation_check = QCheckBox(
            "Require typing DELETE before removing a key"
        )
        self._delete_text_confirmation_check.setAccessibleDescription(
            "When disabled, key deletion only uses the existing delete dialog."
        )
        form.addRow("", self._delete_text_confirmation_check)
        return box

    def _build_reset_box(self) -> QGroupBox:
        box = QGroupBox("Factory reset")
        layout = QVBoxLayout(box)
        layout.addWidget(
            QLabel(
                "Reset GPG Meister to a clean local state. This removes the app config, "
                "local keyring, metadata database, logs, cache, and vault files stored "
                "inside the app data directory on the next launch."
            )
        )
        layout.addWidget(
            QLabel("Externally exported files outside the app-managed folders are not removed.")
        )
        self._btn_factory_reset = QPushButton("Schedule Factory Reset")
        layout.addWidget(self._btn_factory_reset)
        return box

    def _build_button_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        self._btn_save = QPushButton("Save Settings")
        self._btn_save.setDefault(True)
        self._status_label = QLabel()
        self._status_label.setWordWrap(True)
        row.addWidget(self._btn_save)
        row.addWidget(self._status_label, stretch=1)
        return row

    def _connect_signals(self) -> None:
        self._vm.config_saved.connect(lambda: self._set_status("Settings saved.", ok=True))
        self._vm.save_failed.connect(lambda msg: self._set_status(f"Save failed: {msg}", ok=False))
        self._vm.factory_reset_failed.connect(
            lambda msg: self._set_status(f"Factory reset failed: {msg}", ok=False)
        )
        self._vm.factory_reset_scheduled.connect(self._on_factory_reset_scheduled)

        self._locale_combo.currentIndexChanged.connect(self._on_locale_changed)
        self._cipher_combo.currentIndexChanged.connect(self._on_cipher_changed)
        self._kdf_combo.currentIndexChanged.connect(self._on_kdf_changed)
        self._appearance_combo.currentIndexChanged.connect(self._on_appearance_changed)
        self._clipboard_spin.valueChanged.connect(self._vm.set_clipboard_clear_seconds)
        self._backup_spin.valueChanged.connect(self._vm.set_backup_reminder_days)
        self._high_contrast_check.toggled.connect(self._vm.set_high_contrast)
        self._reduce_motion_check.toggled.connect(self._vm.set_reduce_motion)
        self._delete_text_confirmation_check.toggled.connect(
            self._vm.set_require_delete_text_confirmation
        )
        self._hash_chain_check.toggled.connect(self._vm.set_audit_hash_chain)
        self._btn_save.clicked.connect(self._vm.save)
        self._btn_factory_reset.clicked.connect(self._confirm_factory_reset)

    def _load_current(self) -> None:
        cfg = self._vm.config
        _set_combo(self._locale_combo, cfg.locale)
        _set_combo(self._cipher_combo, cfg.cipher.value)
        _set_combo(self._kdf_combo, cfg.kdf_profile.value)
        appearance = (
            AppearanceMode.SYSTEM if cfg.appearance == AppearanceMode.DARK else cfg.appearance
        )
        _set_combo(self._appearance_combo, appearance.value)
        self._clipboard_spin.setValue(cfg.clipboard_clear_seconds)
        self._backup_spin.setValue(cfg.backup_reminder_days)
        self._high_contrast_check.setChecked(cfg.high_contrast)
        self._reduce_motion_check.setChecked(cfg.reduce_motion)
        self._delete_text_confirmation_check.setChecked(cfg.require_delete_text_confirmation)
        self._hash_chain_check.setChecked(cfg.audit.hash_chain)

    def _on_locale_changed(self, idx: int) -> None:
        locale = self._locale_combo.itemData(idx)
        if isinstance(locale, str):
            self._vm.set_locale(locale)

    def _on_cipher_changed(self, idx: int) -> None:
        cipher = _combo_enum_value(self._cipher_combo, idx, CipherAlgorithm)
        if cipher is not None:
            self._vm.set_cipher(cipher)

    def _on_kdf_changed(self, idx: int) -> None:
        profile = _combo_enum_value(self._kdf_combo, idx, KDFProfile)
        if profile is not None:
            self._vm.set_kdf_profile(profile)

    def _on_appearance_changed(self, idx: int) -> None:
        appearance = _combo_enum_value(self._appearance_combo, idx, AppearanceMode)
        if appearance is not None:
            self._vm.set_appearance(appearance)

    def _set_status(self, msg: str, *, ok: bool) -> None:
        self._status_label.setText(msg)
        color = "#006600" if ok else "#cc0000"
        self._status_label.setStyleSheet(f"color: {color};")

    def _confirm_factory_reset(self) -> None:
        answer = QMessageBox.warning(
            self,
            "Schedule factory reset",
            "This will reset GPG Meister to a clean local state on the next launch.\n\n"
            "It will remove the local app config, app-managed GPG keyring, metadata, "
            "logs, cache, and vault files inside the app data directory.\n\n"
            "External files outside the app-managed folders are not removed.\n\n"
            "Do you want to schedule the reset and close the app now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if answer == QMessageBox.StandardButton.Yes:
            confirmation, ok = QInputDialog.getText(
                self,
                "Confirm factory reset",
                "Type RESET to confirm the factory reset.",
            )
            if ok and confirmation.strip().upper() == self._FACTORY_RESET_CONFIRM_TEXT:
                self._vm.schedule_factory_reset()

    def _on_factory_reset_scheduled(self) -> None:
        QMessageBox.information(
            self,
            "Factory reset scheduled",
            "The factory reset was scheduled successfully. The app will close now. "
            "Launch it again to complete the reset.",
        )
        app = QApplication.instance()
        if app is not None:
            app.quit()


def _set_combo(combo: QComboBox, value: object) -> None:
    if (idx := combo.findData(value)) >= 0:
        combo.setCurrentIndex(idx)


def _combo_enum_value(
    combo: QComboBox,
    idx: int,
    enum_type: type[_EnumT],
) -> _EnumT | None:
    try:
        return enum_type(combo.itemData(idx))
    except (TypeError, ValueError):
        return None
