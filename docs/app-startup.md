# App and Startup Flow

This document describes the startup path for GPG Meister.

## Main entry point

The application starts in `src/gpg_meister/app.py`.

The startup flow is:

1. Create the Qt application.
2. Resolve filesystem paths.
3. Configure diagnostic logging.
4. Load `AppConfig` from disk.
5. Install the UI translation.
6. Open the audit log.
7. Resolve a trusted GPG binary.
8. Run environment checks.
9. Create services and the metadata store.
10. Build the main window and all tabs.
11. Optionally show the first-launch wizard.
12. Show backup reminders and stale-backup warnings.
13. Enter the Qt event loop.

## Dependency wiring

`app.py` is the composition root: it creates runtime dependencies and passes them into the layers that need them.

Important runtime objects:

- `MetadataStore` for local SQLite metadata.
- `AuditLog` for append-only security events.
- `GPGService` for low-level GPG work.
- `KeyService`, `MessageService`, and `VaultService` for application logic.
- ViewModels for each UI area.
- Views that bind to those ViewModels.

This keeps lower layers independent from the full desktop application assembly.

## GPG trust flow

The app does not automatically run the first `gpg` binary on `PATH`.

`_resolve_gpg()` in `app.py` calls `startup.gpg_detector.detect()`. If the configured binary is outside the whitelist or its hash changed, the user sees a trust dialog before the binary is accepted.

This trust step is one of the key security controls in the project.

## What the app stores at startup

At startup the app opens:

- the config file
- the audit log
- the SQLite metadata database

It does not load private keys into its own storage. Key material stays in the dedicated GPG home and, during vault work, only in memory.

## Runtime Behavior

The current code already includes a context layer for keys:

- `KeyService` merges GPG key data with metadata from SQLite.
- `key_metadata` stores `label`, `purpose`, `platform`, and `notes`.
- the key detail dialog can edit this context.

This makes the running application more complete than the original plan text in this area.
