# GPG Meister Docs

This folder explains the current codebase in simple English.

These documents describe the real implementation in `src/gpg_meister`, not only the original ideas from `planv2.md`.

## Start here

- [App and Startup Flow](app-startup.md) explains how the app boots, resolves GPG, and wires services and UI.
- [Domain Models](models.md) explains the main Pydantic models and what data they hold.
- [Security Modules](security.md) explains key derivation, authenticated encryption, secure memory, and the vault frame.
- [Service Layer](services.md) explains the business layer around GPG, messages, keys, config, and vaults.
- [Storage Layer](storage.md) explains local files, SQLite metadata, atomic writes, locks, logs, and permissions.
- [UI Layer](ui.md) explains the MVVM-style UI structure and background workers.
- [Startup Checks and GPG Detection](startup.md) explains startup checks and GPG binary trust detection.
- [Plan vs Current Code](plan-vs-code.md) compares `planv2.md` with the current implementation.

## Short architecture map

The app is split into a few clean layers:

- `models/` holds validated domain objects.
- `security/` holds crypto and sensitive-memory helpers.
- `services/` holds application logic and GPG orchestration.
- `storage/` holds local persistence and safe file handling.
- `startup/` checks the machine before the app continues.
- `ui/` holds Qt views, viewmodels, widgets, and workers.
- `app.py` connects everything at runtime.

## Important rule

Private keys and passphrases are never stored in the SQLite metadata database or in the config file. They only flow through the GPG service, the vault flow, and short-lived in-memory buffers.
