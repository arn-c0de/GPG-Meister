"""Application entry point (planv2.md §3).

Creates the QApplication, runs startup checks, wires dependencies, and shows the
main window. Startup errors that are hard failures show a blocking error dialog
and exit without opening the main window.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication, QMessageBox

if TYPE_CHECKING:
    from gpg_meister.models.config import AppConfig
    from gpg_meister.services.gpg_service import GPGService
    from gpg_meister.startup.gpg_detector import DetectedGPG
    from gpg_meister.storage.audit_log import AuditLog
    from gpg_meister.storage.metadata_store import MetadataStore
    from gpg_meister.storage.paths import AppPaths
    from gpg_meister.ui.main_window import MainWindow


_DEFAULT_STYLESHEET: str | None = None
_DEFAULT_PALETTE: QPalette | None = None


def _resolve_gpg(config: AppConfig, paths: AppPaths, audit: AuditLog) -> DetectedGPG:
    """Resolve a trusted GPG binary, showing a trust-pinning dialog when needed.

    Handles USER_OVERRIDE_UNTRUSTED and HASH_MISMATCH interactively; all other
    detection failures are fatal.
    """
    from gpg_meister.models.config import GPGBinaryTrust
    from gpg_meister.services import config_service
    from gpg_meister.startup.gpg_detector import DetectionReason, GPGDetectionError, detect
    from gpg_meister.ui.gpg_trust_dialog import GpgTrustDialog

    while True:
        try:
            return detect(
                user_override_path=config.gpg_binary_path,
                trusted_hash=config.gpg_binary_trusted_hash.sha256
                if config.gpg_binary_trusted_hash
                else None,
                trusted_path=config.gpg_binary_trusted_hash.path
                if config.gpg_binary_trusted_hash
                else None,
                trusted_device=config.gpg_binary_trusted_hash.device
                if config.gpg_binary_trusted_hash
                else None,
                trusted_inode=config.gpg_binary_trusted_hash.inode
                if config.gpg_binary_trusted_hash
                else None,
            )
        except GPGDetectionError as exc:
            if exc.reason not in (
                DetectionReason.USER_OVERRIDE_UNTRUSTED,
                DetectionReason.HASH_MISMATCH,
                DetectionReason.IDENTITY_MISMATCH,
            ):
                QMessageBox.critical(
                    None,
                    "GnuPG not found",
                    "GPG Meister needs GnuPG installed on this computer, but none was found.\n\n"
                    f"Detail: {exc}",
                )
                audit.close()
                sys.exit(1)

            if exc.path is None or exc.new_sha is None:
                QMessageBox.critical(None, "GnuPG trust failed", str(exc))
                audit.close()
                sys.exit(1)

            # For IDENTITY_MISMATCH, we re-prompt the user to re-trust the binary.
            # We already have the new hash and path from detect().
            mismatch = exc.reason in (DetectionReason.HASH_MISMATCH, DetectionReason.IDENTITY_MISMATCH)
            old_sha = (
                config.gpg_binary_trusted_hash.sha256
                if config.gpg_binary_trusted_hash
                else None
            )

            # We need the new device/inode to persist them if the user clicks 'Trust'.
            # We'll get them from another detect() call if the user confirms,
            # or we could have detect() return them in the exception.
            # For now, let's just re-run detect() once more if they confirm.

            dlg = GpgTrustDialog(
                exc.path,
                exc.new_sha,
                mismatch=mismatch,
                old_sha=old_sha,
            )
            if not dlg.exec():
                audit.close()
                sys.exit(1)

            # Re-run detect without trusted_* to get the full metadata of the new binary.
            new_gpg = detect(user_override_path=str(exc.path))
            config = config.model_copy(update={
                "gpg_binary_trusted_hash": GPGBinaryTrust(
                    path=str(new_gpg.path),
                    sha256=new_gpg.sha256,
                    device=new_gpg.device,
                    inode=new_gpg.inode,
                )
            })
            config_service.save(config, paths.config_file)


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("GPG Meister")
    app.setOrganizationName("GPG Meister")
    _remember_default_appearance(app)

    from gpg_meister.storage.factory_reset import perform_pending_factory_reset
    from gpg_meister.storage.log_config import configure_logging
    from gpg_meister.storage.paths import resolve_paths

    paths = resolve_paths()
    paths.ensure()
    try:
        perform_pending_factory_reset(paths)
    except Exception as exc:
        QMessageBox.critical(None, "Factory reset failed", str(exc))
        sys.exit(1)
    configure_logging(log_file=paths.diagnostic_log)

    from gpg_meister.i18n import install_translator, resolve_locale
    from gpg_meister.services import config_service
    from gpg_meister.startup.environment_check import EnvironmentCheckError, run_all_checks
    from gpg_meister.storage.audit_log import AuditLog
    from gpg_meister.ui.main_window import MainWindow

    try:
        config = config_service.load(paths.config_file)
    except config_service.ConfigServiceError as exc:
        QMessageBox.critical(None, "Config check failed", str(exc))
        sys.exit(1)
    _apply_appearance(app, config)

    locale_code = resolve_locale(config.locale)
    install_translator(locale_code)

    audit = AuditLog(paths.audit_log, hash_chain=config.audit.hash_chain)

    gpg = _resolve_gpg(config, paths, audit)

    audit.emit("gpg_binary_resolved", path=str(gpg.path), sha256=gpg.sha256)

    try:
        check_result = run_all_checks(paths, gpg.path)
    except EnvironmentCheckError as exc:
        QMessageBox.critical(None, "Startup check failed", str(exc))
        audit.close()
        sys.exit(1)

    audit.emit(
        "startup_environment_check",
        gpg_version=check_result.gpg_version,
        mlock_available=str(check_result.mlock_available),
        swap_encrypted=str(check_result.swap_encrypted),
        warning_count=str(len(check_result.warnings)),
    )

    from gpg_meister.services.gpg_service import GPGService, GPGServiceConfig
    from gpg_meister.services.key_service import KeyService
    from gpg_meister.services.message_service import MessageService
    from gpg_meister.services.vault_service import VaultService
    from gpg_meister.storage.metadata_store import MetadataStore
    from gpg_meister.ui.help.help_view import HelpView
    from gpg_meister.ui.keys.key_list_view import KeyListView
    from gpg_meister.ui.keys.key_list_viewmodel import KeyListViewModel
    from gpg_meister.ui.messages.decrypt_viewmodel import DecryptViewModel
    from gpg_meister.ui.messages.encrypt_viewmodel import EncryptViewModel
    from gpg_meister.ui.messages.messages_tab import MessagesTabView
    from gpg_meister.ui.messages.sign_viewmodel import SignViewModel
    from gpg_meister.ui.messages.verify_viewmodel import VerifyViewModel
    from gpg_meister.ui.settings.settings_view import SettingsView
    from gpg_meister.ui.settings.settings_viewmodel import SettingsViewModel
    from gpg_meister.ui.vault.vault_export_viewmodel import VaultExportViewModel
    from gpg_meister.ui.vault.vault_tab import VaultTabView

    metadata = MetadataStore(paths.metadata_db)
    gpg_svc = GPGService(
        GPGServiceConfig(
            binary_path=gpg.path,
            home_dir=paths.gnupg_home,
            trusted_sha256=gpg.sha256 if not gpg.is_whitelisted else None,
            trusted_device=gpg.device if not gpg.is_whitelisted else None,
            trusted_inode=gpg.inode if not gpg.is_whitelisted else None,
        )
    )
    key_svc = KeyService(gpg=gpg_svc, audit=audit, metadata=metadata)
    msg_svc = MessageService(gpg=gpg_svc, audit=audit)
    vault_svc = VaultService(gpg=gpg_svc, audit=audit)

    window = MainWindow()
    window.show_startup_results(check_result)

    key_vm = KeyListViewModel(
        key_svc,
        require_delete_text_confirmation=config.require_delete_text_confirmation,
    )
    key_view = KeyListView(key_vm)
    window.install_keys_tab(key_view)

    encrypt_vm = EncryptViewModel(msg_svc, key_svc)
    decrypt_vm = DecryptViewModel(msg_svc)
    sign_vm = SignViewModel(msg_svc, key_svc)
    verify_vm = VerifyViewModel(msg_svc)
    messages_view = MessagesTabView(
        encrypt_vm,
        decrypt_vm,
        sign_vm,
        verify_vm,
        key_svc,
        clipboard_clear_seconds=config.clipboard_clear_seconds,
    )
    window.install_messages_tab(messages_view)

    export_vm = VaultExportViewModel(vault_svc, key_svc)
    _wire_key_inventory_updates(key_vm, encrypt_vm, sign_vm, export_vm, messages_view)
    vault_view = VaultTabView(export_vm, vault_svc)
    window.install_vault_tab(vault_view)

    settings_vm = SettingsViewModel(config, paths)
    settings_view = SettingsView(settings_vm)
    settings_vm.config_saved.connect(lambda: _apply_appearance(app, settings_vm.config))
    settings_vm.config_saved.connect(
        lambda: key_vm.set_require_delete_text_confirmation(
            settings_vm.config.require_delete_text_confirmation
        )
    )
    window.install_settings_tab(settings_view)
    window.install_help_tab(HelpView())
    window.set_current_page(config.last_open_page)

    def _persist_current_page(page_value: str) -> None:
        from gpg_meister.models.config import AppPage

        try:
            page = AppPage(page_value)
        except ValueError:
            return
        settings_vm.persist_last_open_page(page)

    window.current_page_changed.connect(_persist_current_page)

    def _on_key_created(key: object) -> None:
        from gpg_meister.models.key_info import KeyInfo
        if isinstance(key, KeyInfo):
            uid = key.user_ids[0] if key.user_ids else key.fingerprint[-16:]
            window.show_backup_reminder(uid)
            metadata.upsert_key(key.fingerprint, label=uid)

    key_vm.key_created.connect(_on_key_created)

    # Show first-launch wizard if the app keyring is empty.
    if not gpg_svc.list_keys():
        from gpg_meister.ui.keys.first_launch_wizard import FirstLaunchWizard
        wizard = FirstLaunchWizard(gpg.path, key_svc, parent=window)
        wizard.exec()

    window.show()

    # §14.3 Backup-staleness reminder: warn if private keys are newer than last vault export.
    _check_backup_staleness(gpg_svc, metadata, window)

    exit_code = app.exec()
    metadata.close()
    audit.close()
    sys.exit(exit_code)


def _wire_key_inventory_updates(
    key_vm: object,
    encrypt_vm: object,
    sign_vm: object,
    export_vm: object | None,
    messages_view: object | None = None,
) -> None:
    """Refresh dependent key pickers whenever the key inventory changes."""

    signals = getattr(key_vm, "keys_changed", None)
    connect = getattr(signals, "connect", None)
    if not callable(connect):
        return

    def _refresh_dependents(_keys: object) -> None:
        for vm in (encrypt_vm, sign_vm, export_vm):
            if vm is None:
                continue
            loader = getattr(vm, "load_keys", None)
            if callable(loader):
                loader()
        if messages_view is not None:
            refresh = getattr(messages_view, "refresh_share_keys", None)
            if callable(refresh):
                refresh()

    connect(_refresh_dependents)


def _check_backup_staleness(
    gpg_svc: GPGService,
    metadata: MetadataStore,
    window: MainWindow,
) -> None:
    """Emit a status-bar warning if private keys exist that are not in any vault (§14.3)."""
    try:
        private_keys = [k for k in gpg_svc.list_keys() if k.has_private_key]
    except Exception:
        return
    if not private_keys:
        return

    latest_vault_ts = metadata.latest_vault_timestamp()
    if latest_vault_ts is None:
        count = len(private_keys)
        window.show_status(
            f"No vault backup exists — {count} private key(s) are not backed up. "
            "Go to the Vault tab to create a backup.",
            timeout_ms=10_000,
        )
        return

    # Compare newest key import timestamp against latest vault timestamp.
    key_records = {r["fingerprint"]: r["import_timestamp"] for r in metadata.list_keys()}
    vault_ts: str = latest_vault_ts  # narrowed: None branch returned above
    newer = [
        k for k in private_keys
        if (key_records.get(k.fingerprint) or "0") > vault_ts
    ]
    if newer:
        window.show_status(
            f"{len(newer)} private key(s) added since last vault backup. "
            "Go to the Vault tab to update your backup.",
            timeout_ms=10_000,
        )


def _apply_appearance(app: QApplication, config: AppConfig) -> None:
    from gpg_meister.models.config import AppearanceMode

    _remember_default_appearance(app)
    if config.appearance == AppearanceMode.LIGHT:
        app.setPalette(_light_palette(config.high_contrast))
        app.setStyleSheet(_DEFAULT_STYLESHEET or "")
        return

    if _DEFAULT_PALETTE is not None:
        app.setPalette(_DEFAULT_PALETTE)
    app.setStyleSheet(
        _default_mode_stylesheet(config.high_contrast)
        if config.high_contrast
        else (_DEFAULT_STYLESHEET or "")
    )


def _remember_default_appearance(app: QApplication) -> None:
    global _DEFAULT_STYLESHEET, _DEFAULT_PALETTE
    if _DEFAULT_STYLESHEET is None:
        _DEFAULT_STYLESHEET = app.styleSheet()
    if _DEFAULT_PALETTE is None:
        _DEFAULT_PALETTE = QPalette(app.palette())


def _light_palette(high_contrast: bool) -> QPalette:
    palette = QPalette()
    window = QColor("#ffffff")
    base = QColor("#ffffff")
    text = QColor("#000000") if high_contrast else QColor("#1e1e1e")
    button = QColor("#ffffff")
    accent = QColor("#005fcc") if high_contrast else QColor("#2f6feb")
    mid = QColor("#000000") if high_contrast else QColor("#d0d7de")

    palette.setColor(QPalette.ColorRole.Window, window)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, base)
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#f6f8fa"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, base)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, button)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Link, accent)
    palette.setColor(QPalette.ColorRole.Highlight, accent)
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Mid, mid)
    return palette


def _default_mode_stylesheet(high_contrast: bool) -> str:
    if not high_contrast:
        return _DEFAULT_STYLESHEET or ""
    focus = "#ffd60a"
    return (_DEFAULT_STYLESHEET or "") + f"""
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QTableWidget, QTabWidget::pane, QGroupBox {{
    border: 1px solid #ffffff;
}}
QPushButton:focus, QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus, QTableWidget:focus {{
    border: 2px solid {focus};
}}
"""


if __name__ == "__main__":
    main()
