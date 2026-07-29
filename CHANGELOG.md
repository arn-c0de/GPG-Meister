# Changelog

All notable changes to this project will be documented in this file.

## [1.0.5] - 2026-07-29

Smartcard release: hardware tokens (YubiKey, Nitrokey, and other OpenPGP cards)
can now hold the keys GPG Meister works with, and can act as a second way to
unlock a vault backup.

### Added

**Smartcard-held keys**

- Keys whose private half lives on a token are recognised and labelled
  throughout the UI. A new **Storage** column on the Keys tab shows the device
  (`YubiKey 12345678`), with `Local`, `Public only`, and `Secret key elsewhere`
  for the other cases; the key details dialog and the signing-key pickers show
  the same information.
- Decrypting and signing with a card key ask for the **card PIN** instead of a
  passphrase, with the field, placeholder, and hint changing accordingly. The
  PIN travels the existing hardened path — `SecureBytes` to an app-owned pipe to
  `--passphrase-fd`, never in `argv` — because loopback pinentry lets gpg-agent
  ask us for the card PIN just as it asks for a passphrase.
- New **Smartcard** panel on the Keys tab shows the inserted card (device,
  serial, cardholder, reader, remaining PIN attempts) and the keys in its three
  slots, and links them into the app's isolated keyring. Slots whose public key
  is missing locally are called out, with the card's key URL when it has one.
- Card-specific failures are now distinguished from passphrase failures: an
  unplugged token or unavailable reader says so and asks for the token, and a
  rejected PIN warns that cards lock themselves after a few attempts.

**Card management**

- The smartcard panel can now change the user or admin PIN, unblock a locked
  user PIN with the admin PIN, move an existing private key onto the card, and
  generate a fresh key set on the device.
- These drive GnuPG's interactive editors through `--command-fd`, answering
  prompts **by keyword** rather than position, so a script that no longer matches
  a GnuPG version cannot answer the wrong question — notably "Replace existing
  keys?". An unscripted prompt aborts the run and reports which prompt was
  asked. `--batch` is dropped for these runs (GnuPG refuses its editors under
  it); loopback pinentry is kept, so PINs still never leave an app-owned pipe.
- Destructive actions are gated twice: the service refuses an occupied slot
  unless the caller passes an explicit overwrite flag, and the dialogs only pass
  it after the user types `REPLACE`. Moving a key also requires typing `MOVE`,
  since GnuPG leaves only a stub behind. Generating on-card keeps GnuPG's
  off-card backup of the encryption key on by default.
- Not verified against physical hardware — see `docs/smartcard.md`.

**Vaults unlockable by a smartcard**

- A vault can now be created with a token as an additional unlock method. Such
  vaults use format **version 3**: the payload is encrypted with a random file
  key that is wrapped once per unlock method ("key slot") — one slot for the
  master passphrase, one per selected token key. Opening the vault needs either.
- The master passphrase slot is written by default, so a lost or broken token
  cannot orphan a backup. Ticking *Token only* omits it, producing a vault the
  token alone can open; the option becomes available only once a token key is
  selected, and states plainly that losing the token destroys the backup.
- The vault import wizard offers "Smartcard PIN" as an unlock method when the
  file advertises one. Which methods a vault supports is read from its header
  alone, before any credential is entered.
- Vaults created without a token keep format version 2, byte-for-byte as before,
  so they remain readable by earlier releases.

### Fixed

- Field 15 of GnuPG's secret-key listing was read as "token serial" when it is
  in fact overloaded: `+` (secret key present locally), `#` (not available
  here), or a serial. Local keys were consequently flagged as stubs in the
  secret listing.
- The token serial is now carried into the public key listing as well, so
  smartcard-backed keys are recognisable everywhere instead of only in the
  secret listing. A serial that appears on a subkey (the common layout: offline
  primary, encryption subkey on the card) is attributed to its primary key.

## [1.0.4] - 2026-05-29

Security and quality release following a full multi-angle audit. No remotely
exploitable vulnerabilities were found; the fixes below close locally-scoped
weaknesses and harden defense-in-depth.

### Security

**Signature verification**

- Signature validity is now derived from GnuPG's `[GNUPG:]` status records
  rather than the process exit code. Previously a message signed by a **revoked
  or expired key** (`REVKEYSIG` / `EXPKEYSIG` / `EXPSIG`) — for which gpg still
  exits 0 — was reported end-to-end as a valid signature, defeating revocation.
  A new `SignatureStatus` (`VALID` / `INVALID` / `REVOKED_KEY` / `EXPIRED_KEY` /
  `EXPIRED_SIG` / `ERROR` / `NONE`) is surfaced in the decrypt and verify views
  with the specific rejection reason. A signature is `VALID` only with
  `GOODSIG` + `VALIDSIG` and no downgrade record.

**Audit log**

- Added a monotonic `seq` counter to hash-chained records so front/middle
  truncation and record removal are detectable even if an attacker recomputes
  the hash links; `verify_chain` enforces seq contiguity. The chain is now
  documented honestly as "internally consistent", not cryptographically
  authentic (unkeyed SHA-256 is forgeable by a same-uid actor).
- `verify_chain` and the tail scan open the log and `.tip` with `O_NOFOLLOW`.
- Write failures are tracked and surfaced (`dropped_records` + an in-band
  `dropped_audit_records` field) instead of being silently swallowed.
- The sensitive-key deny-list is unified in one module, matched
  case-insensitively, and the diagnostic filter redacts recursively through
  nested dicts/lists.

**Clipboard**

- Copied secrets are now cleared from the clipboard on application quit (an
  `aboutToQuit` flush), not only by a timer that is lost if the app closes
  first. The configured auto-clear delay is honoured at every call site.

**In-memory secrets**

- `_zero_bytes_object` refuses to wipe length-≤1 `bytes` (CPython caches these
  as shared singletons; zeroing one corrupted interpreter-wide state, reachable
  from single-character passphrases), bails out on non-CPython runtimes, and
  reports failures instead of swallowing them. `SecureBytes` gained a `__del__`
  backstop and surfaces mlock failures.
- `kdf.derive_key` feeds the mutable bytearray to argon2 directly, only copying
  to immutable `bytes` on a real `TypeError`.
- The legacy "all-in-manifest" vault import keeps private-key armor as `bytes`
  (never decoded to an unzeroable `str`) and wipes the intermediates.

**UI**

- Unexpected exceptions no longer echo their raw text (file paths, key ids, gpg
  stderr) into the UI; a generic message with a correlation reference is shown
  and the detail is logged.
- The signing passphrase is read once at submit and never stored on the
  encrypt ViewModel; decrypted plaintext auto-clears after the clipboard delay
  and is scrubbed on hide; the passphrase "Show" toggle auto-reverts after 10 s.

**Storage & startup**

- Factory reset overwrites the metadata DB (and `-wal`/`-shm`), the audit and
  diagnostic logs, and vault files before deletion — not just the GPG home —
  and documents that secure erase is best-effort on SSD/CoW storage.
- `GPGService` pins the binary's SHA-256 for the session (including whitelisted
  binaries) and re-hashes before each invocation, catching an in-place rewrite
  of the same inode.
- The "core dumps could not be disabled" check is a strong warning instead of a
  hard startup block, so the app still launches on seccomp/musl/hardened hosts.
- `atomic_write` fchmods the fd after open so the mode is not weakened by umask;
  `MetadataStore` drops the thread-unsafe global umask juggling.

### Tooling

- `ruff` is clean across `src` and `mypy --strict` on `src` reports zero errors.
- Added a GitHub Actions CI workflow gating ruff, mypy(src) and pytest.
- The macOS bundle version is single-sourced from `gpg_meister.__version__`;
  `install.sh` detects non-Debian systems and exits with guidance.

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
