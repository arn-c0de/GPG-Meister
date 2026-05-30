"""Application entry point (planv2.md §3).

Creates the QApplication, runs startup checks, wires dependencies, and shows the
main window. Startup errors that are hard failures show a blocking error dialog
and exit without opening the main window.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtGui import QColor, QIcon, QPalette
from PySide6.QtWidgets import QApplication, QMessageBox

if TYPE_CHECKING:
    from gpg_meister.models.config import AppConfig
    from gpg_meister.services.gpg_service import GPGService
    from gpg_meister.startup.gpg_detector import DetectedGPG
    from gpg_meister.storage.audit_log import AuditLog
    from gpg_meister.storage.metadata_store import MetadataStore
    from gpg_meister.storage.paths import AppPaths
    from gpg_meister.ui.keys.key_list_viewmodel import KeyListViewModel
    from gpg_meister.ui.main_window import MainWindow
    from gpg_meister.ui.messages.encrypt_viewmodel import EncryptViewModel
    from gpg_meister.ui.messages.messages_tab import MessagesTabView
    from gpg_meister.ui.messages.sign_viewmodel import SignViewModel
    from gpg_meister.ui.vault.vault_export_viewmodel import VaultExportViewModel


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
        trust = config.gpg_binary_trusted_hash
        try:
            return detect(
                user_override_path=config.gpg_binary_path,
                trusted_hash=trust.sha256 if trust else None,
                trusted_path=trust.path if trust else None,
                trusted_device=trust.device if trust else None,
                trusted_inode=trust.inode if trust else None,
            )
        except GPGDetectionError as exc:
            if exc.reason not in (
                DetectionReason.USER_OVERRIDE_UNTRUSTED,
                DetectionReason.HASH_MISMATCH,
                DetectionReason.IDENTITY_MISMATCH,
                DetectionReason.NOT_ROOT_OWNED,
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

            # For HASH/IDENTITY mismatch, re-prompt the user to re-trust the
            # binary; detect() already gave us the new hash and path.
            mismatch = exc.reason in (DetectionReason.HASH_MISMATCH, DetectionReason.IDENTITY_MISMATCH)
            old_sha = trust.sha256 if trust else None

            dlg = GpgTrustDialog(
                exc.path,
                exc.new_sha,
                mismatch=mismatch,
                old_sha=old_sha,
            )
            if not dlg.exec():
                audit.close()
                sys.exit(1)

            # Re-run detect with the newly accepted hash so non-whitelisted
            # binaries don't raise USER_OVERRIDE_UNTRUSTED again.
            new_gpg = detect(
                user_override_path=str(exc.path),
                trusted_hash=exc.new_sha,
                trusted_path=str(exc.path),
            )
            config = config.model_copy(update={
                "gpg_binary_trusted_hash": GPGBinaryTrust(
                    path=str(new_gpg.path),
                    sha256=new_gpg.sha256,
                    device=new_gpg.device,
                    inode=new_gpg.inode,
                )
            })
            config_service.save(config, paths.config_file)


def _app_icon() -> QIcon:
    path = Path(__file__).parent / "logo.png"
    return QIcon(str(path)) if path.exists() else QIcon()


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("GPG Meister")
    app.setOrganizationName("GPG Meister")
    app.setWindowIcon(_app_icon())
    _remember_default_appearance(app)

    from gpg_meister.storage.factory_reset import perform_pending_factory_reset
    from gpg_meister.storage.log_config import configure_logging
    from gpg_meister.storage.paths import resolve_paths

    paths = resolve_paths()
    paths.ensure()
    try:
        perform_pending_factory_reset(paths)
    except (OSError, RuntimeError) as exc:
        # Catch the expected I/O / refusal failures; let programming errors
        # propagate to the top-level handler instead of masking them here
        # (this runs before logging is configured).
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

    # Make the configured auto-clear delay the application-wide default and
    # ensure any copied secret is wiped from the clipboard on quit (M3).
    from gpg_meister.ui.clipboard import install_quit_handler, set_default_clear_seconds

    set_default_clear_seconds(config.clipboard_clear_seconds)
    install_quit_handler()

    locale_code = resolve_locale(config.locale)
    install_translator(locale_code)

    from gpg_meister.storage.audit_log import verify_chain

    if config.audit.hash_chain and paths.audit_log.exists():
        ok, count = verify_chain(paths.audit_log)
        if not ok:
            QMessageBox.warning(
                None,
                "Audit log integrity warning",
                f"The audit log at {paths.audit_log} failed chain verification "
                f"after {count} record(s). It may have been tampered with.",
            )

    audit = AuditLog(paths.audit_log, hash_chain=config.audit.hash_chain)

    gpg = _resolve_gpg(config, paths, audit)

    audit.emit("gpg_binary_resolved", path=str(gpg.path), sha256=gpg.sha256)

    from gpg_meister.startup.environment_check import CheckSeverity

    try:
        check_result = run_all_checks(paths, gpg.path)
    except EnvironmentCheckError as exc:
        QMessageBox.critical(None, "Startup check failed", str(exc))
        audit.close()
        sys.exit(1)

    error_checks = [w for w in check_result.warnings if w.severity == CheckSeverity.ERROR]
    if error_checks:
        details = "\n".join(f"• {w.message}" for w in error_checks)
        QMessageBox.critical(
            None,
            "Unsafe environment — startup blocked",
            f"GPG Meister cannot start safely:\n\n{details}",
        )
        audit.close()
        sys.exit(1)

    audit.emit(
        "startup_environment_check",
        gpg_version=check_result.gpg_version,
        mlock_available=str(check_result.mlock_available),
        core_dumps_disabled=str(check_result.core_dumps_disabled),
        swap_encrypted=str(check_result.swap_encrypted),
        warning_count=str(len(check_result.warnings)),
    )

    from gpg_meister.models.config import AppPage
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
    vault_svc = VaultService(gpg=gpg_svc, audit=audit, metadata=metadata)

    window = MainWindow()
    window.show_startup_results(check_result)

    key_vm = KeyListViewModel(
        key_svc,
        require_delete_text_confirmation=config.require_delete_text_confirmation,
    )
    key_view = KeyListView(key_vm)
    window.install_tab(AppPage.KEYS, key_view)

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
    window.install_tab(AppPage.MESSAGES, messages_view)

    export_vm = VaultExportViewModel(vault_svc, key_svc)
    _wire_key_inventory_updates(key_vm, encrypt_vm, sign_vm, export_vm, messages_view)
    vault_view = VaultTabView(export_vm, vault_svc)
    window.install_tab(AppPage.VAULT, vault_view)

    settings_vm = SettingsViewModel(config, paths)
    settings_view = SettingsView(settings_vm)

    def _on_settings_saved() -> None:
        cfg = settings_vm.config
        _apply_appearance(app, cfg)
        key_vm.set_require_delete_text_confirmation(cfg.require_delete_text_confirmation)
        set_default_clear_seconds(cfg.clipboard_clear_seconds)

    settings_vm.config_saved.connect(_on_settings_saved)
    window.install_tab(AppPage.SETTINGS, settings_view)
    window.install_tab(AppPage.HELP, HelpView())
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
            uid = key.primary_user_id
            window.show_backup_reminder(uid)
            metadata.upsert_key(key.fingerprint, label=uid)

    key_vm.key_created.connect(_on_key_created)

    # Show first-launch wizard if the app keyring is empty.
    if not gpg_svc.list_keys():
        from gpg_meister.ui.keys.first_launch_wizard import FirstLaunchWizard
        wizard = FirstLaunchWizard(gpg.path, key_svc, parent=window)
        wizard.exec()

    window.show()

    # §14.3 Backup-staleness reminder: defer to avoid blocking window appearance.
    from PySide6.QtCore import QTimer
    QTimer.singleShot(0, lambda: _check_backup_staleness(gpg_svc, metadata, window))

    exit_code = app.exec()
    metadata.close()
    audit.close()
    sys.exit(exit_code)


def _wire_key_inventory_updates(
    key_vm: KeyListViewModel,
    encrypt_vm: EncryptViewModel,
    sign_vm: SignViewModel,
    export_vm: VaultExportViewModel | None,
    messages_view: MessagesTabView | None = None,
) -> None:
    """Refresh dependent key pickers whenever the key inventory changes.

    ``export_vm``/``messages_view`` are optional because not every caller wires
    them; the rest are concrete viewmodels with known signals.
    """

    def _refresh_dependents(_keys: object) -> None:
        for vm in (encrypt_vm, sign_vm, export_vm):
            if vm is not None:
                vm.load_keys()
        if messages_view is not None:
            messages_view.refresh_share_keys()

    key_vm.keys_changed.connect(_refresh_dependents)


def _check_backup_staleness(
    gpg_svc: GPGService,
    metadata: MetadataStore,
    window: MainWindow,
) -> None:
    """Emit a status-bar warning if private keys exist that are not in any vault (§14.3)."""
    from PySide6.QtCore import QThreadPool

    from gpg_meister.ui.worker import Worker

    def _do() -> list[object]:
        return [k for k in gpg_svc.list_keys() if k.has_private_key]

    def _on_result(private_keys: object) -> None:
        if not isinstance(private_keys, list) or not private_keys:
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
        key_records = {r["fingerprint"]: r["import_timestamp"] for r in metadata.list_keys()}
        vault_ts: str = latest_vault_ts
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

    w = Worker(_do)
    w.signals.result.connect(_on_result)
    QThreadPool.globalInstance().start(w)


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
