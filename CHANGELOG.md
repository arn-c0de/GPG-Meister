# Changelog

All notable changes to this project will be documented in this file.

## [1.0.3] - 2026-05-17

### Security

**Passphrase and key material lifetime in memory**

- Rewrote the GPG subprocess interface to deliver passphrases exclusively via OS
  pipes (`--passphrase-fd`). The passphrase is written to a kernel pipe and
  zeroed immediately after the pipe is flushed, rather than being held on the heap
  for the full duration of the GPG operation (up to 60 s).
- Zeroed all intermediate `bytes` objects produced by `.encode()` before they are
  abandoned to the garbage collector. Fixed 9+ call sites across all viewmodels
  (key creation, message decrypt/encrypt/sign, vault export, vault import) and the
  service layer (KDF, vault create/open).
- Zeroed the argon2 input bytes copy (`_secret`) in `kdf.derive_key()` via
  `_zero_bytes_object()` immediately after `hash_secret_raw()` returns.
- Zeroed `manifest_bytes` (full msgpack-serialised vault manifest containing all
  private key armored blocks) immediately after AEAD encryption, inside
  `vault_service.create()`.
- Zeroed the AEAD-decrypted vault plaintext (`plaintext`) after manifest parsing
  in `vault_service._open()`.
- Replaced loop-based memory zeroing with `ctypes.memset()` throughout, preventing
  JIT or compiler optimizations from eliding the wipe.
- Extracted `_zero_bytes_object()` as a shared helper in `secure_bytes.py` to
  eliminate duplicated CPython-internal zeroing code.

**Clipboard**

- Added platform-specific MIME sensitivity hints to all clipboard writes so that
  clipboard history managers (KDE, Windows, macOS) suppress capture of sensitive
  text (`x-kde-passwordManagerHint: secret`,
  `ExcludeClipboardContentFromMonitorProcessing`, `org.nspasteboard.TransientType`,
  etc.).
- Clipboard auto-clear uses independent per-copy timers with a snapshot comparison
  before clearing, so concurrent copies do not interfere with each other's timers.

**Vault**

- Added import KDF floor validation: vault headers with `time_cost` or
  `memory_cost` below the application minimum are rejected before AEAD decryption
  is attempted, preventing resource-exhaustion via crafted vault headers.
- Enforced 0o700 permissions on the vault parent directory at creation time (was
  world-readable 0o755).
- Vault format now explicitly rejects zero-length ciphertext before handing off to
  AEAD, producing a clearer error than a generic authentication failure.
- Tightened msgpack deserialization limits inside the vault service: `max_str_len`
  reduced from 256 MiB to 64 KiB (sufficient for any armored key string).
- Fixed TOCTOU race in `factory_reset.py`: `is_symlink()` check added immediately
  before `shutil.rmtree()` to close the window between the earlier `reject_symlink`
  call and the actual deletion.

**Key import — smuggled-key handling**

- Vault import now aborts with `ServiceError` and records `OUTCOME_FAILED` in the
  audit log if an unexpected key (not in the planned fingerprint set) cannot be
  removed from the keyring after import. Previously, the exception was swallowed
  and the audit entry was written before the deletion was even attempted.
- `key_service.import_armored()` applies the same fix: smuggled-key deletion
  failure is now audited and raises `ServiceError` instead of silently continuing.

**Audit log**

- Forbidden-key checks in `_check_payload_keys()` now recurse into nested
  `list`/`tuple` values, closing a bypass where sensitive data inside a sequence
  was not inspected.
- Hash-chained audit log writes a `.tip` file after each append;
  `verify_chain()` now compares the final hash against the tip file so tail
  truncation of the log is detectable.
- Audit log write failures (e.g. disk full) now fall back to stderr instead of
  propagating the `OSError`, preventing a storage error from appearing as a failed
  key operation to the user.
- Audit log and diagnostic log files are opened with `O_NOFOLLOW` on POSIX.

**GPG binary trust**

- GPG binary inode and device number are recorded at startup and verified before
  every invocation to detect binary substitution at runtime.

**SQLite / metadata store**

- Added `PRAGMA busy_timeout = 5000` so a second concurrent app instance waits up
  to 5 s for the write lock rather than immediately raising "database is locked".

### Added

- Per-key passphrase unlock UI for vault export: each private key selected for
  backup can be individually unlocked with its own GPG passphrase before the vault
  is written.
- App icon and logo displayed in the taskbar and title bar.
- Help view with inline tooltips on technical terms.
- Decryption help instructions in the Messages tab.
- `gpgmeister` entry-point alias; `install.sh` links it globally and bootstraps
  `uv` automatically using the official Astral installer.
- Two-key vault backup create/decrypt/import integration test.
- zram devices whitelisted in the swap encryption check (swap-in-RAM, no disk
  persistence).

### Fixed

- Passphrase for per-key vault unlock was cleared by a `QLineEdit.clear()` signal
  race: `active_fp` is now nulled before calling `clear()` so the resulting
  `passphrase_changed` signal cannot overwrite the stored passphrase with an empty
  string.
- Background `Worker` kept its `_Signals` QObject alive until cross-thread signal
  events are delivered via `QTimer.singleShot(0, _release)`, preventing silent
  signal drops under GC pressure.
- Smartcard (stub) key export errors in vault backup are handled gracefully; the
  key is included as public-only instead of aborting the backup.
- Vault export layout no longer clips the passphrase section on smaller windows.
- Inherited `VIRTUAL_ENV` environment variable cleared in the start script to
  prevent environment pollution.

### Maintenance

- Updated all dependencies.
- Entry-point renamed from `gpg-meister` to `gpgmeister` for shell ergonomics.

## [1.0.2] - 2026-05-14

### Security
- Fixed multiple vulnerabilities identified in the 2026-05-15 and 2026-05-14 audits.
- Enforced root ownership for whitelisted GPG binaries.
- Improved mlock detection and swap encryption checks.
- Added timeouts to all GPG operations.
- Restricted SecureBytes leakage in AEAD and KDF paths.
- Implemented atomic deletion for secret and public keys.
- Added device/inode tracking for GPG binary trust verification.
- Scoped trust settings and reduced passphrase lifetime.

### Added
- Key favorites: star toggle, delete guard, and grouped sorting.
- GPG trust-pinning dialog for non-whitelisted binaries.
- Share Key tab for exporting public keys.
- GnuPG module and home directory access to Flatpak packaging.

### Changed
- Moved blocking GPG and SQLite calls off the UI thread for better responsiveness.
- Simplified key deletion by removing redundant passphrase prompts.
- Increased maximum vault armor length to 8 MB.
- Switched project license to MIT.

### Fixed
- Duplicate backup banner and improved WarningBanner actions.
- Theme settings persistence.
- Stuck "New Key" action.
- Signal delivery in GUI workers.

### Documentation
- Added Security Policy and Code of Conduct.
- Added contribution guidelines.
- Updated README with screenshots and project status.

## [1.0.1] - 2026-05-12

### Added
- Initial release with core PGP management features.
- Support for encryption, decryption, signing, and verification.
- Vault management with export and import wizards.
- Audit logging for security-sensitive operations.
- Multi-language support (English and German).
- Automated GPG binary detection and hardening.

### Technical Foundation
- Phase 1: Foundation, crypto primitives, and core models.
- Phase 2: GPG integration and binary-path hardening.
- Phase 3: Storage primitives and service completion.
- Phase 4: UI shell and navigation.
- Phase 5: Key management views.
- Phase 6: Message operations (Encrypt/Decrypt/Sign/Verify).
- Phase 7: Vault views and backup reminders.
- Phase 8: Help system, settings, and end-to-end security tests.
- Phase 9: Packaging and release tooling.
