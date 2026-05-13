# Service Layer

The service layer lives in `src/gpg_meister/services`.

These modules hold application logic. They sit between the UI and the lower-level crypto, storage, and GPG integration code.

## `gpg_service.py`

This is the low-level adapter around `python-gnupg`.

It is one of the most security-sensitive files in the project.

Main responsibilities:

- create and manage a dedicated `gnupg.GPG` instance
- enforce safe GPG options like `--batch` and `--pinentry-mode loopback`
- list, find, create, import, export, delete, sign, verify, encrypt, and decrypt keys/messages
- convert raw GPG output into app models
- keep passphrases out of command-line arguments

Important real-world detail:

the code does not trust the library completely. It adds its own checks so passphrases do not appear in argv by accident.

## `key_service.py`

This is the key lifecycle layer used by the UI.

It adds:

- audit logging
- metadata merge logic
- import conflict analysis
- a clean API for key context updates

Current behavior:

- `list_keys()` merges GPG key data with SQLite metadata
- `find()` returns enriched `KeyInfo`
- `update_context()` saves `label`, `purpose`, `platform`, and `notes`

This means the UI works with one complete key object instead of manually joining data from two systems.

## `message_service.py`

This module wraps message operations:

- encrypt
- decrypt
- sign
- verify

It mainly adds audit logging and a stable result model for the UI.

Compared with the plan, the current implementation is direct and pragmatic. The service is thin because the sensitive subprocess handling is already concentrated inside `GPGService`.

## `vault_service.py`

This module orchestrates vault export and import.

It is the highest-level security workflow in the app.

Create flow:

1. validate fingerprints
2. acquire a file lock
3. export public or private key material from GPG
4. build a `VaultManifest`
5. derive a vault key from the master passphrase
6. encrypt the manifest
7. write the vault atomically
8. write a SHA-256 sidecar
9. emit audit events

Import flow:

- open the vault
- decrypt and validate the manifest
- preview keys without changing the local keyring
- import selected entries into GPG

Nothing in this module writes plaintext key material to disk.

## `config_service.py`

This module loads and saves `AppConfig` as TOML.

Main points:

- returns defaults if the config file does not exist
- validates loaded data with Pydantic
- saves atomically
- omits `None` because TOML has no null value

## `validation.py`

This file is small but important.

It validates:

- fingerprints
- emails
- user names
- key lengths
- expiry strings
- accidental passphrase leaks into argv

This protects the subprocess boundary before values reach GPG.
