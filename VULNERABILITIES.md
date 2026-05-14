# Verified Vulnerabilities - GPG Meister

This document lists security vulnerabilities and quality issues verified in the codebase as of 2026-05-14.

## 1. Environment & Memory Protection

### 1.1 `mlock()` Return Code Not Checked — FIXED
*   **Location:** `src/gpg_meister/startup/environment_check.py:175`
*   **Issue:** The `check_mlock()` function calls `libc.mlock` but ignores the return value. It may report success even if memory locking fails.
*   **Fix:** Return value is now checked (`return ret == 0`).

### 1.2 Swap File Exposure — FIXED
*   **Location:** `src/gpg_meister/startup/environment_check.py:204`
*   **Issue:** `_check_swap_linux()` only inspects `/dev/mapper/` block devices. Swap files are skipped, potentially leaving sensitive data exposed on unencrypted swap partitions.
*   **Fix:** Non-block-device swap entries now emit a `swap_file_unverified` warning.

### FIXED 1.3 Immutable Secret Clearing Failure
*   **Location:** `src/gpg_meister/security/kdf.py:105`
*   **Issue:** `derive_key()` attempts to zero-out sensitive `raw` bytes via reassignment. Since Python `bytes` are immutable, the original sensitive memory is not cleared.

### FIXED 1.4 Untracked Secret Copies in AEAD & KDF
*   **Location:** `src/gpg_meister/security/aead.py:53, 67`, `src/gpg_meister/security/kdf.py:84`
*   **Issue:** `bytes(key.view())` or `bytes(passphrase.view())` are called, creating untracked, immutable copies of sensitive key material in memory.

### 1.5 Sensitive Data Leaks in UI/ViewModel
*   **Location:** `src/gpg_meister/ui/keys/key_create_viewmodel.py:105`, `src/gpg_meister/ui/clipboard.py:13`, `src/gpg_meister/ui/widgets/clipboard_button.py:46`
*   **Issue:** Passphrases and copied secrets are stored as regular Python strings. These objects are not zeroed and persist in memory until garbage collection.

## 2. Configuration & Permission Risks

### 2.1 Unsafe `~/.gnupg` Permission Mutation
*   **Location:** `src/gpg_meister/ui/keys/first_launch_wizard.py`, `src/gpg_meister/services/gpg_service.py:135`
*   **Issue:** Initializing `GPGService` on the user's real `~/.gnupg` triggers `ensure_dir()` which `chmod`s the directory to `0700`, potentially altering existing system permissions.

### 2.2 TOCTOU Symlink Vulnerabilities
*   **Location:** `src/gpg_meister/storage/permissions.py`, `src/gpg_meister/storage/file_lock.py`, `src/gpg_meister/storage/metadata_store.py:105`
*   **Issue:** Symlink checks are performed separately from file opens/chmods, creating race windows for symlink-swapping attacks.

### FIXED 2.3 Insecure Temp File Location
*   **Location:** `src/gpg_meister/services/gpg_service.py:397`
*   **Issue:** `verify()` creates temporary signature files inside the GPG home directory. If the home is the user's system `~/.gnupg`, this can lead to permission issues or leftover artifacts in a shared space.

## 3. Data Handling & UI Security

### 3.1 Insecure Clipboard Usage — FIXED
*   **Location:** `src/gpg_meister/ui/messages/share_key_view.py`, `src/gpg_meister/ui/messages/sign_view.py`, `src/gpg_meister/ui/keys/key_detail_view.py`
*   **Issue:** Direct writes to the clipboard bypass the centralized `copy_text` helper, failing to trigger the auto-clear timer.
*   **Fix:** All three call sites now use `copy_text()`.

### 3.2 Shallow Security Filters — FIXED
*   **Location:** `src/gpg_meister/storage/audit_log.py:100`
*   **Issue:** `_check_payload()` only scans top-level keys for forbidden names. Nested dictionaries can bypass redaction and leak secrets into logs.
*   **Fix:** `_check_payload_keys()` is now recursive over nested dicts.

### 3.3 Audit Log Crash on Windows — FIXED
*   **Location:** `src/gpg_meister/storage/audit_log.py:91`
*   **Issue:** `_actor()` calls `os.getuid()`, which is unavailable on Windows.
*   **Fix:** `os.getuid()` is only called on non-Windows platforms.

### FIXED 3.4 Missing Trust Verification on Decrypt/Verify
*   **Location:** `src/gpg_meister/services/message_service.py:130`
*   **Issue:** Signatures are reported as "valid" based only on cryptography. Signer trust is ignored, allowing identity spoofing via matching names on untrusted keys.

## 4. Logical & Metadata Inconsistencies

### 4.1 Missing Metadata Update on Vault Creation — FIXED
*   **Location:** `src/gpg_meister/services/vault_service.py:200`
*   **Issue:** Vault creation fails to notify `MetadataStore`, breaking backup-staleness reminders.
*   **Fix:** `VaultService` now accepts an optional `metadata` parameter and calls `add_vault_record()` after a successful create. Wired in `app.py`.

### 4.2 Redundant GPG Secret Inventory (Performance DoS) — FIXED
*   **Location:** `src/gpg_meister/services/gpg_service.py:181`
*   **Issue:** `list_keys()` performs redundant GPG process calls to scan for secret keys.
*   **Fix:** When `secret=True`, all returned rows are already secret keys — `_secret_fingerprints()` is no longer called.

### 4.3 O(N^2) Performance in Audit Log Hash-Chaining
*   **Location:** `src/gpg_meister/storage/audit_log.py:84, 115`
*   **Issue:** Quadratic time complexity for log writes because the entire file is re-scanned on every entry.

## 5. Architectural & Format Risks

### 5.1 Vault Key Armor Length Constraint
*   **Location:** `src/gpg_meister/models/vault.py:27`
*   **Issue:** `MAX_VAULT_ARMOR_LENGTH` (2MB) may be too small for complex keys.

### 5.2 Resource Exhaustion in Vault Import — FIXED
*   **Location:** `src/gpg_meister/services/vault_service.py:131`
*   **Issue:** `msgpack.unpackb()` is used without memory limits, allowing DoS via maliciously crafted vault payloads.
*   **Fix:** `max_buffer_size=MAX_CIPHERTEXT_SIZE` passed to `msgpack.unpackb()`.

## 6. UI Stability & Implementation Gaps

### 6.1 Blocking Service Calls in UI Thread
*   **Location:** `src/gpg_meister/ui/keys/key_detail_view.py`, `src/gpg_meister/ui/messages/share_key_view.py`, `app.py:342`
*   **Issue:** Synchronous calls to GPG or SQLite block the event loop, causing the UI to freeze.

## 7. Supply Chain & Packaging

### 7.1 Sandbox Isolation Gaps
*   **Location:** `packaging/flatpak/io.github.arn-c0de.GPGMeister.yaml`
*   **Issue:** The Flatpak manifest lacks GnuPG as a module. Furthermore, it doesn't grant access to the host `~/.gnupg`, which will cause the `FirstLaunchWizard` to fail or lead to insecure permission workarounds.

## 8. Additional Deep Findings

### 8.1 Startup "Error" Checks Are Non-Blocking — FIXED
*   **Location:** `src/gpg_meister/startup/environment_check.py:119-151, 154-166`, `src/gpg_meister/app.py:156-205`
*   **Issue:** Checks with `severity=ERROR` were ignored at startup; the app continued even under unsafe conditions.
*   **Fix:** `app.py` now collects ERROR-severity warnings after `run_all_checks()` and exits with a critical dialog if any are present.

### 8.2 Public-Key Import Filter Miss Legacy Secret-Key Armor — FIXED
*   **Location:** `src/gpg_meister/services/key_service.py:25-27, 310-320`
*   **Issue:** The public-import gate blocked only `"-----BEGIN PGP PRIVATE KEY BLOCK-----"` but not the legacy `"-----BEGIN PGP SECRET KEY BLOCK-----"` header.
*   **Fix:** `SECRET_KEY_BLOCK` constant added and checked alongside `PRIVATE_KEY_BLOCK` in `_validate_public_import_blob()`.

### 8.3 Unbounded File Read in Public Key Import Dialog — FIXED
*   **Location:** `src/gpg_meister/ui/keys/public_key_import_view.py:90-99`
*   **Issue:** `_load_file()` read the full file into memory before any size check.
*   **Fix:** `stat().st_size` is checked against `MAX_PUBLIC_KEY_IMPORT_BYTES` before reading.

### 8.4 SQLite WAL/SHM Permission Gap — FIXED
*   **Location:** `src/gpg_meister/storage/metadata_store.py:74-82`
*   **Issue:** Sidecar chmod ran before `PRAGMA journal_mode=WAL`, so newly created `-wal`/`-shm` files inherited the process umask.
*   **Fix:** Sidecar chmod moved to after `executescript(_SCHEMA)`.

### 8.5 Missing Runtime Timeouts for Core GPG Operations
*   **Location:** `src/gpg_meister/services/gpg_service.py:69-73, 201-417`
*   **Issue:** `GPGServiceConfig.timeout_seconds` exists, but only `version()` uses it. All other GPG operations can hang indefinitely.

### 8.6 Trust-Pinning Revalidation Can Dead-End Startup — FIXED
*   **Location:** `src/gpg_meister/app.py:102-104`
*   **Issue:** After the user accepted a re-trust, `detect()` was called without `trusted_hash/trusted_path`, causing `USER_OVERRIDE_UNTRUSTED` again for non-whitelisted binaries.
*   **Fix:** `detect()` is now called with `trusted_hash=exc.new_sha` and `trusted_path=str(exc.path)` after user confirms.

### 8.7 Hash-Chained Audit Logs Are Not Verified at Startup — FIXED
*   **Location:** `src/gpg_meister/app.py:150-169`
*   **Issue:** `verify_chain()` was never called automatically; tampered records went undetected.
*   **Fix:** `verify_chain()` is called before opening the audit log if `hash_chain` is enabled; a warning dialog is shown on failure.

### 8.8 Whitelist Trust Does Not Enforce Strong Ownership
*   **Location:** `src/gpg_meister/startup/gpg_detector.py:24-45, 142-148, 206-214, 281-288`
*   **Issue:** `detect()` records `is_root_owned` but does not enforce it. A non-root-owned binary at a whitelisted path is still accepted.

### 8.9 Factory-Reset Marker Write Follows Symlinks — FIXED
*   **Location:** `src/gpg_meister/storage/factory_reset.py:24-34`
*   **Issue:** `request_factory_reset()` and `perform_pending_factory_reset()` did not guard against the marker path being a symlink.
*   **Fix:** `reject_symlink_tree(marker)` is called before reading or writing the marker in both functions.

### 8.10 Startup Error Severity Is Downgraded in UI — FIXED
*   **Location:** `src/gpg_meister/ui/main_window.py:85-89`
*   **Issue:** `show_startup_results()` only mapped `config_world_readable` to `ErrorSeverity.ERROR`; the newer codes `config_unsafe_permissions` and `config_readable_by_others` were silently downgraded to WARNING.
*   **Fix:** Both new codes added to the ERROR set in `show_startup_results()`.

### 8.11 Vault Import Fingerprint Scope Bypass (Confused Deputy) — FIXED
*   **Location:** `src/gpg_meister/services/vault_service.py:350-372`
*   **Issue:** `import_keys()` appended all fingerprints returned by GPG, allowing crafted vault entries to smuggle extra keys.
*   **Fix:** Only `entry.fingerprint` is appended to `imported` if it appears in the GPG-returned list; extra fingerprints from the blob are discarded.

### FIXED 8.12 Keystroke-level Passphrase Exposure via Strength Assessment
*   **Location:** `src/gpg_meister/ui/widgets/passphrase_field.py:65-75`
*   **Issue:** `PassphraseField` emits the `passphrase_changed` signal on every keystroke, which triggers `assess(text)` in the ViewModel. This creates many short-lived Python strings in memory (e.g., "P", "Pa", "Pas", ...), increasing the attack surface for memory scraping or swap-file exposure.

### FIXED 8.13 Passphrase Captured in ViewModel Closure
*   **Location:** `src/gpg_meister/ui/messages/decrypt_viewmodel.py:84-95`
*   **Issue:** The passphrase is captured in a `lambda: passphrase` closure within `submit()`. This extends the lifetime of the sensitive string until the lambda object is garbage collected, which may be delayed if the GPG worker task is stalled or if a traceback holds a reference to the frame.

### FIXED 8.14 Binary Data Corruption Risk in GPG Service
*   **Location:** `src/gpg_meister/services/gpg_service.py:345-385`
*   **Issue:** `encrypt()` and `sign()` decode binary `bytes` input into Python `str` using `surrogateescape` before passing them to `python-gnupg`. While `surrogateescape` is designed for round-tripping, this is unnecessary as `python-gnupg` handles binary data directly. This adds memory overhead and potential for data corruption if the resulting string is treated as text.

### FIXED 8.15 Vault Sidecar Checksum Error Prevents Recovery
*   **Location:** `src/gpg_meister/services/vault_service.py:445-455`
*   **Issue:** `_open()` raises `VaultServiceError` on SHA-256 mismatch, making it impossible to open a vault if only the sidecar is corrupted. This contradicts the UI `error_catalog.py`, which defines a "vault_checksum_mismatch" warning with an "open anyway" option.

### FIXED 8.16 First-Launch Wizard Private Key Import Omission
*   **Location:** `src/gpg_meister/ui/keys/first_launch_wizard.py:145-155`
*   **Issue:** The wizard displays "Has private: yes" for keys in the system keyring, but `_do_import` calls only `export_public_key()`. This leads to a major UX/Security mismatch where users believe they have imported their secret keys pair when only the public component was copied.

### FIXED 8.17 `KeyService.plan_import` Pre-Parsing Denial of Service (DoS)
*   **Location:** `src/gpg_meister/services/key_service.py:155-185`
*   **Issue:** `plan_import()` calls `scan_keys_mem()` on the full input blob before enforcing the `MAX_PUBLIC_KEY_IMPORT_COUNT` limit. An attacker can supply a large block (up to 2MB) containing thousands of small keys, forcing GPG to perform exhaustive parsing and metadata extraction before the batch is rejected.

### FIXED 8.18 SecureBytes Pattern Failure (Ubiquitous Leakage)
*   **Location:** `src/gpg_meister/services/gpg_service.py`, `src/gpg_meister/security/kdf.py`, `src/gpg_meister/security/aead.py`
*   **Issue:** While `SecureBytes` is used to carry passphrases, almost every consumer immediately calls `bytes(sb.view())` or `sb.decode("utf-8")`. This creates immutable, non-zeroable copies of the secret on the Python heap, effectively defeating the memory-protection guarantees of the `SecureBytes` class.

### FIXED 8.19 GPG `delete_key` Inconsistency Race
*   **Location:** `src/gpg_meister/services/gpg_service.py:315-325`
*   **Issue:** `delete_key()` performs secret and public key deletions in two separate GPG calls. If the process is terminated or crashes between these calls, the secret key is removed but the public key remains as an "orphan" in the keyring, leading to an inconsistent application state.

### 8.20 `EnvironmentCheck.py` Incomplete Verification
*   **Location:** `src/gpg_meister/startup/environment_check.py:175-210`
*   **Issue:** `check_mlock` only attempts to load `libc.so.6`, failing on non-glibc systems (e.g., Alpine). `_check_swap_linux` relies on a shallow `/dev/mapper/` string check which can be easily bypassed or misreport encrypted LVM volumes as unencrypted if named non-standardly.
