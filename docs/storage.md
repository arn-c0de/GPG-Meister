# Storage Layer

The storage code lives in `src/gpg_meister/storage`.

It handles the local filesystem safely and keeps non-secret application state.

## `metadata_store.py`

This is the local SQLite metadata database.

It stores:

- key metadata
- vault export records
- app preferences

Current `key_metadata` fields:

- `fingerprint`
- `label`
- `purpose`
- `platform`
- `notes`
- `import_timestamp`
- `last_used_timestamp`

Important boundary:

the metadata database does not store private keys, passphrases, or decrypted vault content.

The implementation also includes a small migration step so older databases gain the newer context columns automatically.

## `paths.py`

This module resolves platform-aware application paths.

On Linux and macOS it follows XDG-style locations.
On Windows it uses the roaming app data area.

The `AppPaths` object exposes common locations like:

- config file
- GPG home
- vault directory
- metadata database
- audit log
- diagnostic log

## `audit_log.py`

This is a separate, append-only audit trail for security-relevant events.

Key protections:

- only whitelisted event names are allowed
- forbidden sensitive payload keys are rejected
- optional hash chaining is supported
- records are flushed and synced on write

This is stricter than a normal application log. That is intentional.

## `atomic_write.py`

This module prevents half-written files.

It writes to a temporary file in the same directory, `fsync()`s it, replaces the target atomically, and then syncs the parent directory on POSIX.

This is used for config and vault writing.

## `file_lock.py`

This module provides advisory cross-platform file locking.

It is used by the vault flow so two app instances do not write the same vault file at the same time.

The design is practical:

- POSIX uses `fcntl.flock`
- Windows uses `msvcrt.locking`
- lock files are separate from vault files

## `permissions.py`

This file checks and creates safe filesystem permissions.

It is mostly POSIX-focused:

- directories default to `0700`
- sensitive files default to `0600`
- Windows is treated differently because NTFS ACLs are the real control there

## Real implementation note

The storage layer is not only about persistence. It also contains some of the app's security posture:

- safe file permissions
- crash-safe writes
- audit integrity
- minimal metadata storage
