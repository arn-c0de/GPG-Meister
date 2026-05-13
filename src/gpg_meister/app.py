"""Application entry point (planv2.md §3).

Creates the QApplication, runs startup checks, wires dependencies, and shows the
main window. Startup errors that are hard failures show a blocking error dialog
and exit without opening the main window.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QApplication, QMessageBox

if TYPE_CHECKING:
    from gpg_meister.services.gpg_service import GPGService
    from gpg_meister.storage.metadata_store import MetadataStore
    from gpg_meister.ui.main_window import MainWindow


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("GPG Meister")
    app.setOrganizationName("GPG Meister")

    from gpg_meister.storage.log_config import configure_logging
    from gpg_meister.storage.paths import resolve_paths

    paths = resolve_paths()
    paths.ensure()
    configure_logging(log_file=paths.diagnostic_log)

    from gpg_meister.i18n import install_translator, resolve_locale
    from gpg_meister.services import config_service
    from gpg_meister.startup.environment_check import EnvironmentCheckError, run_all_checks
    from gpg_meister.startup.gpg_detector import GPGDetectionError, detect
    from gpg_meister.storage.audit_log import AuditLog
    from gpg_meister.ui.main_window import MainWindow

    config = config_service.load(paths.config_file)

    locale_code = resolve_locale(config.locale.value)
    install_translator(locale_code)

    audit = AuditLog(paths.audit_log, hash_chain=config.audit.hash_chain)

    try:
        gpg = detect(
            user_override_path=config.gpg_binary_path,
            trusted_hash=config.gpg_binary_trusted_hash.sha256
            if config.gpg_binary_trusted_hash
            else None,
        )
    except GPGDetectionError as exc:
        QMessageBox.critical(
            None,
            "GnuPG not found",
            f"GPG Meister needs GnuPG installed on this computer, but none was found.\n\n"
            f"Detail: {exc}",
        )
        audit.close()
        sys.exit(1)

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
    from gpg_meister.ui.keys.key_list_view import KeyListView
    from gpg_meister.ui.keys.key_list_viewmodel import KeyListViewModel
    from gpg_meister.ui.messages.decrypt_viewmodel import DecryptViewModel
    from gpg_meister.ui.messages.encrypt_viewmodel import EncryptViewModel
    from gpg_meister.ui.messages.messages_tab import MessagesTabView
    from gpg_meister.ui.messages.sign_viewmodel import SignViewModel
    from gpg_meister.ui.messages.verify_viewmodel import VerifyViewModel
    from gpg_meister.ui.vault.vault_export_viewmodel import VaultExportViewModel
    from gpg_meister.ui.vault.vault_tab import VaultTabView

    gpg_svc = GPGService(GPGServiceConfig(binary_path=gpg.path, home_dir=paths.gnupg_home))
    key_svc = KeyService(gpg=gpg_svc, audit=audit)
    msg_svc = MessageService(gpg=gpg_svc, audit=audit)
    vault_svc = VaultService(gpg=gpg_svc, audit=audit)
    metadata = MetadataStore(paths.metadata_db)

    window = MainWindow()
    window.show_startup_results(check_result)

    key_vm = KeyListViewModel(key_svc)
    key_view = KeyListView(key_vm)
    window.install_keys_tab(key_view)

    encrypt_vm = EncryptViewModel(msg_svc, key_svc)
    decrypt_vm = DecryptViewModel(msg_svc)
    sign_vm = SignViewModel(msg_svc, key_svc)
    verify_vm = VerifyViewModel(msg_svc)
    messages_view = MessagesTabView(encrypt_vm, decrypt_vm, sign_vm, verify_vm)
    window.install_messages_tab(messages_view)

    export_vm = VaultExportViewModel(vault_svc, key_svc)
    vault_view = VaultTabView(export_vm, vault_svc)
    window.install_vault_tab(vault_view)

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


if __name__ == "__main__":
    main()
