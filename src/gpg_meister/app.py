"""Application entry point (planv2.md §3).

Creates the QApplication, runs startup checks, wires dependencies, and shows the
main window. Startup errors that are hard failures show a blocking error dialog
and exit without opening the main window.
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication, QMessageBox


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
    from gpg_meister.storage.metadata_store import MetadataStore
    from gpg_meister.ui.keys.key_list_view import KeyListView
    from gpg_meister.ui.keys.key_list_viewmodel import KeyListViewModel

    gpg_svc = GPGService(GPGServiceConfig(binary_path=gpg.path, home_dir=paths.gnupg_home))
    key_svc = KeyService(gpg=gpg_svc, audit=audit)
    metadata = MetadataStore(paths.metadata_db)

    window = MainWindow()
    window.show_startup_results(check_result)

    key_vm = KeyListViewModel(key_svc)
    key_view = KeyListView(key_vm)
    window.install_keys_tab(key_view)

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

    exit_code = app.exec()
    metadata.close()
    audit.close()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
