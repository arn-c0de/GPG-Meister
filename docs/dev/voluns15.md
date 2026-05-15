# Security Vulnerability Report - 2026-05-15

**Project:** GPG-Meister  
**Auditor:** Gemini CLI  
**Status:** Deep Audit (Phases 1-6) Completed — All 10 findings FIXED 2026-05-15  

---

## Summary of Findings

The security audit of GPG-Meister was conducted in six exhaustive phases. The audit identified two **High** severity implementation vulnerabilities, one **Medium** severity logic flaw, and several **Low** severity / **Architectural** risks related to binary hardening and memory safety.

The project demonstrates a level of security maturity significantly higher than typical desktop applications, though surgical fixes are needed for the identified edge cases.

---

## 1. [HIGH] Denial of Service (OOM) via Unbounded Sidecar Read — **FIXED**

### Description
The `_read_sidecar_digest` function in `vault_service.py` uses `sidecar.read_bytes()[:256]`.

### Impact
An attacker can trigger an Out-Of-Memory crash by placing a multi-gigabyte `.sha256` file next to a vault.

### Fix
Changed to `sidecar.open("rb").read(256)` so at most 256 bytes are read from disk.

---

## 2. [HIGH] Flatpak Sandbox Misconfiguration (Startup Failure) — **FIXED**

### Description
The Flatpak manifest bundles GnuPG at `/app/bin/gpg`, but `gpg_detector.py` does not whitelist this path.

### Impact
Total failure to launch for Linux users installing via Flatpak.

### Fix
Added `/app/bin/gpg` and `/app/bin/gpg2` to `_LINUX_WHITELIST` in `gpg_detector.py`.

---

## 3. [HIGH-PRIVILEGE] TOCTOU in GPG Binary Resolution — **FIXED**

### Description
There is a Time-of-Check to Time-of-Use (TOCTOU) window between when `GPGDetector` verifies a binary (checking hash, inode, and permissions) and when `GPGService` actually executes it.

### Impact
A local attacker with high-frequency filesystem access could potentially swap the trusted binary with a malicious one immediately after the check but before execution.

### Fix
`GPGService.__init__` now records the binary's device and inode immediately after the full hash-based validation. A new `_assert_binary_not_swapped()` method re-checks device/inode before every GPG invocation (`_run()`, `delete_key()`, `version()`), shrinking the TOCTOU window to near-zero.

---

## 4. [MEDIUM] Key Smuggling via Armored Block Concatenation — **ALREADY FIXED**

### Description
GnuPG imports all keys in a block; the app only audits the first/intended one.

### Impact
Keyring pollution and potential UI confusion leading to data encryption for an attacker's key.

### Fix
Already addressed: `vault_service.import_keys()` detects and immediately deletes any fingerprint returned by GPG that was not in the intended set. `key_service.plan_import()` surfaces all keys to the UI before commit, and `MAX_PUBLIC_KEY_IMPORT_COUNT` caps batch sizes.

---

## 5. [LOW] Missing Memory Pinning on Windows — **FIXED**

### Description
`SecureBytes` uses `mlock` on Linux/macOS but does not implement `VirtualLock` on Windows.

### Impact
On Windows, sensitive passphrases and keys are not pinned to RAM and may be swapped to disk in the pagefile, potentially exposing them if full-disk encryption is not active.

### Fix
`secure_bytes.py` now loads `kernel32` on Windows and dispatches `_try_mlock`/`_try_munlock` to `VirtualLock`/`VirtualUnlock` via ctypes, mirroring the POSIX mlock path.

---

## 6. [LOW] Missing Binary Hardening in Build Toolchain — **FIXED**

### Description
The build scripts (`build_appimage.sh`, `build_macos_app.sh`) do not pass hardening flags (like symbol stripping or extra stack protection) to `PyInstaller` or `linuxdeploy`.

### Impact
The resulting binaries carry unnecessary symbols and metadata, aiding reverse engineering and potentially lacking platform-standard exploit mitigations.

### Fix
`packaging/windows/gpg-meister.spec`: `strip=True` in both `EXE` and `COLLECT`. `packaging/macos/setup.py`: `"strip": True` in py2app OPTIONS.

---

## 7. [LOW / OBSCURE] Potential UI Injection via i18n glossary — **FIXED**
Malicious translations can inject HTML/JS into the help view.

### Fix
`_build_glossary_html()` in `help_view.py` now passes every term and definition through `html.escape()` before interpolating into the HTML template.

---

## 8. [LOW / OBSCURE] SQLite Persistence Side-Channel — **FIXED**
WAL/SHM sidecars are created with default permissions before being tightened to `0600`.

### Fix
`MetadataStore.__init__` now sets `umask(0o177)` around the `sqlite3.connect()` call so any files SQLite creates during connection setup (WAL, SHM) inherit at most `0o600`. The post-connect explicit `_fchmod_nofollow` is retained as belt-and-suspenders.

---

## 9. [LOW] FileLock Invalidation via Atomic Write — **FIXED**
Atomic replacement of the target file invalidates the advisory lock.

### Fix
`FileLock._acquire_posix()` now re-checks that the fd's inode matches the current filesystem inode at `self._lock_path` after acquiring the `flock`. If they diverge (lock file was deleted and re-created by a concurrent holder), it re-opens and retries, closing the stale-lock-file race.

---

## 10. [LOW] Batch Parameter Injection via Passphrase Newlines — **FIXED**
Newlines in passphrases can inject control directives during key generation.

### Fix
`gpg_service.generate_key()` now checks `pass_bytes` for `\n` and `\r` before calling `gen_key_input()` and raises `GPGValidationError` if found.

---

## Audit Methodology
- Manual code review across six depth phases.
- Build script and toolchain hardening analysis.
- Platform-specific memory security auditing (POSIX vs Windows).
- Transitive dependency version verification (`uv.lock`).
