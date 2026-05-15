# Security Vulnerability Report - 2026-05-15

**Project:** GPG-Meister
**Auditors:** Gemini CLI (initial pass), Claude Sonnet 4.6 (deep review — all source files read)
**Status:** Full consolidated report
**Scope:** All 35 Python source files in `src/gpg_meister/`

---

## Summary of Findings

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 3 |
| Medium | 7 |
| Low | 6 |
| Informational | 1 |
| Chained attack scenarios | 4 |

No backdoors or intentionally inserted weaknesses were found. The codebase has strong
fundamentals — ChaCha20-Poly1305 AEAD, Argon2id KDF, hardened subprocess handling,
`O_NOFOLLOW` throughout, hash-chained audit log, GPG binary whitelist with root-
ownership check. All findings below are design gaps or ordering mistakes, not
fundamental architectural failures.

---

## CRITICAL

---

### C-1 — TOCTOU: `os.chmod` After `open()` in `log_config.py`

**File:** `src/gpg_meister/storage/log_config.py:157–162`
**Status:** FIXED

#### Description

```python
reject_symlink(path)             # T₀ — symlink check
fh = path.open("a", ...)         # T₁ — file created or opened
if sys.platform != "win32":
    os.chmod(path, 0o600)        # T₂ — follows *path*, not the open fd
```

`reject_symlink` runs at T₀. Between T₁ and T₂ an attacker with write access to the
parent directory can unlink the newly-created `diagnostic.log` and place a symlink at
that path pointing to any target (e.g. `~/.ssh/authorized_keys`, `/etc/crontab`).
`os.chmod(path, 0o600)` then follows the symlink and sets the mode on the target.

This is the exact class of bug that `_fchmod_nofollow` was written to prevent. Every
other `chmod` in the codebase uses `_fchmod_nofollow` — `log_config.py` is the one
remaining exception. On systems where the application runs as root (Flatpak sandbox
setup scripts or packaging), this becomes an arbitrary root-privilege `chmod`.

#### Mitigation

Replace line 161 with `os.fchmod(fh.fileno(), 0o600)`. The fd is already open; chmod
on the fd is immune to path-substitution after the `open()`.

---

## HIGH

---

### H-1 — Key Smuggling Mitigation is Incomplete: Vault Import Still Pollutes Keyring

**File:** `src/gpg_meister/services/vault_service.py:388–412`
**Status:** FIXED

#### Description

The existing `if entry.fingerprint in results` guard (line 411) only filters the
**return value** — GPG has already imported all keys in the armored blob at line 394:

```python
results = self._gpg.import_key(armored)   # ALL keys in blob imported here

if entry.fingerprint in results:          # only controls what is *returned*
    imported.append(entry.fingerprint)
```

Smuggled keys — including private keys — silently enter the application keyring. The
audit log records only the intended fingerprint. The UI shows a clean import. The user
has no way to detect this.

`key_service.import_armored()` (lines 233–248) is comparatively honest: it returns and
logs *all* fingerprints GPG actually imported. The vault import path is the silent one.

#### Mitigation

After `import_key(armored)`, compute `extra = set(results) - {entry.fingerprint}`.
For each fingerprint in `extra`, call `gpg.delete_key(fp)` immediately and emit an
audit warning event. This ensures the keyring ends in the state the user consented to.

---

### H-2 — Over-Count Guard Fires After Import in `key_service.import_armored`

**File:** `src/gpg_meister/services/key_service.py:236–244`
**Status:** FIXED

#### Description

```python
fps = self._gpg.import_key(armored)           # ALL keys imported here
...
if len(fps) > MAX_PUBLIC_KEY_IMPORT_COUNT:    # guard fires AFTER import
    raise ValueError("too many keys in one import batch")
```

If a blob contains 33 keys, `import_key()` runs and all 33 enter the keyring. Then
`ValueError` is raised. The caller sees an exception and believes nothing was imported
— but the keyring is permanently polluted. The error cannot undo the import.

`plan_import` has a pre-import header-count check (line 198–200) on the literal string
`PUBLIC_KEY_BLOCK`, but `import_armored` bypasses this and calls GPG directly.

#### Mitigation

Move the count check into `_validate_public_import_blob()` using
`armored.count(PUBLIC_KEY_BLOCK)` before any GPG call. The post-import check at line
244 can remain as a secondary defence but must not be the primary gate.

---

### H-3 — Vault Import Wizard Blocks UI Thread Twice with Full Argon2id + AEAD

**Files:** `src/gpg_meister/ui/vault/vault_import_view.py:130–184, 264–304`
**Status:** FIXED

#### Description

The vault import wizard calls the vault service synchronously on the UI thread in two
separate wizard pages.

**Page 2 — `_PassphrasePage.validatePage()` (line 143):**
```python
QApplication.processEvents()   # cosmetic; does NOT start a thread
with SecureBytes.from_bytes(pp_text.encode()) as pp:
    self._preview = self._vault_svc.preview(...)   # Argon2id + AEAD on UI thread
```

**Page 4 — `_ResultPage.initializePage()` (line 291):**
```python
QApplication.processEvents()
with SecureBytes.from_bytes(pp_text.encode()) as pp:
    imported = self._vault_svc.import_keys(...)    # second Argon2id + AEAD + GPG
```

Both calls run the full Argon2id KDF (256 MB RAM, 3 iterations — ~1–3 s) plus AEAD
decryption on the UI thread. `QApplication.processEvents()` only drains the Qt event
queue and then returns to the still-blocking code. The UI freezes for several seconds
**twice** per vault import.

Additionally, `_ResultPage.initializePage()` reads the passphrase back from the
QLineEdit widget via `pp_page.passphrase()` (line 282), creating a new plain `str` on
the heap. `del` is not called before the KDF runs. The QLineEdit is cleared only at
line 303 — after the entire import finishes.

Commit 56d0bf0 ("UI: move blocking GPG/SQLite calls off the UI thread") fixed this
class of problem for GPG and SQLite paths. The vault import wizard was not updated.

#### Mitigation

Wrap both `vault_svc.preview()` and `vault_svc.import_keys()` in `Worker` objects
dispatched to `QThreadPool`, consistent with every other ViewModel in the codebase.
The wizard page progression must be made asynchronous: disable Next/Finish while the
Worker runs; re-enable and advance in the `finished` signal handler.

---

## MEDIUM

---

### M-1 — Key Smuggling via Armored Block Concatenation *(Gemini finding #1 — confirmed and extended)*

**Files:** `src/gpg_meister/services/key_service.py`, `src/gpg_meister/services/vault_service.py`
**Status:** FIXED

This is the original Gemini finding. See H-1 and H-2 above for the deeper analysis
showing that the existing partial mitigation in `vault_service.py` is insufficient (it
filters the return value only, not the keyring), and that the over-count guard in
`key_service.py` fires after import.

**Impact as originally stated:** Keyring pollution / shadowing. A smuggled key with
the same User ID as a trusted contact can be inadvertently selected as an encryption
recipient. See Chain 1 for a full exploitation scenario.

**Mitigation:** As described in H-1 and H-2.

---

### M-2 — Inconsistent Passphrase Lifecycle Across ViewModels *(extends Gemini finding #2)*

**Files:** Multiple ViewModels
**Status:** FIXED

#### Description

Gemini identified that passphrases pass through immutable Python `str`/`bytes` objects.
A full read of all ViewModels reveals the problem is broader and inconsistently handled.

**Correctly handled — `decrypt_viewmodel.py:53–54`:**
```python
pp_secure = SecureBytes.from_bytes(pp_str.encode()) if pp_str else None
del pp_str    # explicit delete
```

**Not handled — `sign_viewmodel.py:81–83`:**
```python
pp_str   = get_passphrase()    # str — never deleted
pp_bytes = pp_str.encode()     # immutable bytes — never deleted
# both captured in the Worker closure, persist in _live_workers until execution
```

**Not handled — `encrypt_viewmodel.py:44, 86–87`:**
```python
self._passphrase = value      # str stored as field
...
pp_bytes = self._passphrase.encode()
self._passphrase = ""         # drops reference; does NOT zero memory
# pp_bytes captured in closure without del
```

**Not handled — `vault_export_viewmodel.py:44–46, 95–99`:**
Three passphrase str fields. Both `master_bytes` and `gpg_bytes` are immutable heap
objects captured in the Worker closure without `del`. At peak: original str + encoded
bytes + SecureBytes buffer — three simultaneous copies per passphrase.

**Not handled — `key_create_viewmodel.py:46, 107–108`:**
```python
pp_secure = SecureBytes.from_bytes(self._passphrase.encode())
self._passphrase = ""   # assignment drops reference; does NOT zero
```

**Not handled — `vault_import_view.py:282–290`:**
`_ResultPage.initializePage()` reads the passphrase back from the widget as a fresh
plain `str` via `pp_page.passphrase()` without calling `del` before the blocking import.

#### Additionally: Every GPGService call converts SecureBytes → immutable str

`gpg_service.py:263, 275, 301, 391, 408, 429`:
```python
pass_bytes = bytes(passphrase.view())       # immutable bytes
pass_str   = pass_bytes.decode("utf-8")     # immutable str
kwargs["passphrase"] = pass_str             # str also in dict
```
Architecturally unavoidable (python-gnupg requires a Python str), but every GPG
operation creates at minimum three unzeroable objects containing the passphrase. This
is a known limitation per planv2.md §4.4 but not documented explicitly there.

#### Mitigation

Apply the `decrypt_viewmodel.py` pattern uniformly: encode immediately, wrap in
`SecureBytes`, call `del pp_str` and `del pp_bytes` before any closure captures them.
For the GPGService calls: document as a known architectural limitation; minimise scope
so the str and bytes objects are released immediately after each call returns.

---

### M-3 — Factory Reset Does Not Securely Wipe Private Key Material *(extends Gemini finding #2)*

**File:** `src/gpg_meister/storage/factory_reset.py:39–47`
**Status:** FIXED

#### Description

```python
shutil.rmtree(directory)
```

`shutil.rmtree` unlinks files — it does not overwrite byte content. On SSDs, unlinked
data persists in flash memory until the block is recycled by wear levelling. The GPG
home directory (`data_dir/gnupg/private-keys-v1.d/`) contains private key material.
After a factory reset triggered by a lost or stolen device, a forensic tool on the
raw storage medium can reconstruct these files. See Chain 3 for a full scenario.

#### Mitigation

Before calling `rmtree`, walk every file under `paths.data_dir/gnupg/` and overwrite
its content with zeros (open fd, write zeros, fsync, close, then unlink). On Linux,
`shred -u` achieves this via subprocess. This is best-effort on SSDs with transparent
wear levelling but eliminates trivial recovery without specialised hardware.

---

### M-4 — Audit Hash Chain: Hashing Re-Encoded String Instead of Raw Bytes

**File:** `src/gpg_meister/storage/audit_log.py:226–228, 269–271`
**Status:** FIXED

#### Description

Both `_scan_for_last_hash()` and `verify_chain()` compute the chain hash by decoding
the raw bytes with `errors="replace"`, re-encoding, then hashing:

```python
# _scan_for_last_hash (line 227–228)
line = raw.decode("utf-8", errors="replace")
return hashlib.sha256(line.encode("utf-8")).hexdigest()

# verify_chain (line 271)
prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()
```

An attacker who modifies a log record by injecting non-UTF-8 bytes causes
`errors="replace"` to substitute U+FFFD identically in both the write-time scan and
the read-time verify. Both sides compute the same garbled hash. The tampering is
therefore **undetectable** by chain verification — the chain still passes. See Chain 4
for a full exploitation scenario.

#### Mitigation

Hash the **raw bytes** of the line before any decoding. Change both occurrences from
`hashlib.sha256(line.encode("utf-8"))` to `hashlib.sha256(raw)` where `raw` is the
`bytes` object read from the file. The decoded `line` string is still needed for JSON
parsing; only the hashing input changes.

---

### M-5 — `Worker._live_workers` Retains Passphrase Closures While Queued

**File:** `src/gpg_meister/ui/worker.py:24–48`
**Status:** FIXED

#### Description

```python
_live_workers: typing.ClassVar[set[Worker]] = set()
...
def __init__(self, fn, ...):
    self._live_workers.add(self)       # added at creation time
...
def run(self):
    ...
    finally:
        self._live_workers.discard(self)  # removed only after execution
```

Workers are added to `_live_workers` at construction and removed only after `run()`
completes. The closures in `sign_viewmodel.py`, `encrypt_viewmodel.py`, and
`vault_export_viewmodel.py` capture immutable `bytes` objects holding passphrases
(M-2). If `QThreadPool.globalInstance()` is at thread capacity, new Workers queue. Their
captured passphrase bytes stay in `_live_workers`, fully exposed in process memory and
not zeroed by `SecureBytes.close()` — the pre-wrap `bytes` objects are separate from
the `SecureBytes` buffer.

On slower hardware with several concurrent operations, two or more plaintext passphrases
can accumulate simultaneously in `_live_workers`.

#### Mitigation

The root fix is M-2: call `del pp_bytes` before any closure captures them. As a
secondary measure, document that security-sensitive Workers must not capture passphrase
bytes by value in their closures.

---

### M-6 — Diagnostic Log Content Filter Missing `SECRET KEY BLOCK` + Deny-List Drift

**File:** `src/gpg_meister/storage/log_config.py:23–44`
**Status:** FIXED

#### Description

```python
_CONTENT_TRIGGERS: tuple[str, ...] = (
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN PGP MESSAGE-----",
)
```

RFC 4880 defines `-----BEGIN PGP SECRET KEY BLOCK-----` as an equally valid armor
header for secret key material. A GPG error message or debug trace containing a
"SECRET KEY BLOCK" armored key passes the content filter unredacted and is written to
`diagnostic.log` on disk.

Additionally the diagnostic-log deny list (`_DENY_LIST`) and the audit-log
forbidden-key list (`audit_log.FORBIDDEN_KEYS`) have drifted apart:

| Key | `_DENY_LIST` (log_config) | `FORBIDDEN_KEYS` (audit_log) |
|---|---|---|
| `salt` | yes | **no** |
| `armored_private` | yes | **no** |

`salt` (base64 KDF salt) can appear in audit records. An audit event with key
`armored_private` would pass audit validation since `FORBIDDEN_KEYS` only blocks the
exact key name `private_key_armored`.

#### Mitigation

1. Add `"-----BEGIN PGP SECRET KEY BLOCK-----"` to `_CONTENT_TRIGGERS`.
2. Extract the deny list into a single shared constant imported by both `log_config`
   and `audit_log`, so any future addition updates both lists atomically.

---

### M-7 — `config_service._dump_toml`: Control Characters Not Escaped

**File:** `src/gpg_meister/services/config_service.py:33–45`
**Status:** FIXED

#### Description

The custom TOML serialiser escapes `\\`, `\n`, and `"` but not other characters that
the TOML spec (§2.3) forbids inside basic strings:

```python
escaped = (
    value.replace("\\", "\\\\")
    .replace("\n", "\\n")
    .replace('"', '\\"')
)
```

U+0000–U+001F (except tab U+0009) must be escaped as `\uXXXX`. `\r` (U+000D), NUL
(U+0000), and all other control characters are written verbatim. The `GPGBinaryTrust.path`
field is a bare `str` with no Pydantic control-character restriction. A path containing
`\r` or `\x00` produces a syntactically invalid `config.toml` that `tomllib.loads()`
rejects on the next launch — bricking the configuration without any data loss.

#### Mitigation

Escape all U+0000–U+001F characters except `\t` as `\uXXXX` sequences in
`_format_toml_value()`. Alternatively, replace the custom serialiser with `tomli_w`.

---

## LOW

---

### L-1 — `first_launch_wizard._do_import()`: Non-Whitelisted Binary Causes Silent Failure

**File:** `src/gpg_meister/ui/keys/first_launch_wizard.py:169–185`
**Status:** FIXED

#### Description

```python
system_svc = GPGService(
    GPGServiceConfig(
        binary_path=self._select_page._binary,
        home_dir=_SYSTEM_GNUPG,
        # trusted_sha256 not passed
    )
)
```

For users who configured a non-whitelisted custom GPG binary (saved as `GPGBinaryTrust`
in `config.toml`), `_revalidate_binary()` calls `detect(trusted_hash=None)`. Because the
binary is not in the platform whitelist and no hash is supplied, `detect()` raises
`GPGDetectionError(USER_OVERRIDE_UNTRUSTED)`. Line 184 catches this with a silent
`_log.warning`. The wizard closes normally. The user incorrectly believes their system
keys have been imported.

#### Mitigation

Pass the already-validated binary's trust info through the wizard constructor. Replace
the silent `_log.warning` with a visible error dialog.

---

### L-2 — `clipboard.py`: Singleton Timer, Second Copy Silently Drops First Auto-Clear

**File:** `src/gpg_meister/ui/clipboard.py:8–37`
**Status:** FIXED

#### Description

`_copied_text` and `_timer` are module-level globals. A second `copy_text()` call
before the first timer fires overwrites `_copied_text` and restarts the single timer:

```python
_copied_text = text                           # overwrites previous value
_timer.start(clear_after_seconds * 1000)      # resets the 60-second window
```

If Alice copies decrypted plaintext (timer starts), then copies a fingerprint, the
plaintext's 60-second auto-clear is silently cancelled. The stated security property —
"sensitive clipboard content is cleared after 60 seconds" — fails without any
indication to the user.

#### Mitigation

Use a per-copy `QTimer` with a captured snapshot rather than a singleton, so each
sensitive copy has its own independent expiry.

---

### L-3 — Audit Log Actor Field Spoofable via `USER` Environment Variable

**File:** `src/gpg_meister/storage/audit_log.py:96–101`
**Status:** FIXED

#### Description

```python
name = os.environ.get("USER") or os.environ.get("USERNAME")
```

An attacker who controls the environment before process launch can set `USER=alice` to
impersonate `alice` in all audit records. Low impact in practice — the audit log is a
forensics tool, not an access control mechanism — but it allows a malicious process
running as the same OS user to write falsely attributed records.

#### Mitigation

Use `pwd.getpwuid(os.geteuid()).pw_name` (POSIX), which reads from `/etc/passwd` rather
than the environment and is immune to env-var injection.

---

### L-4 — `verify()`: Temp Signature File Not Cleaned on SIGKILL

**File:** `src/gpg_meister/services/gpg_service.py:449–459`
**Status:** FIXED

#### Description

```python
with tempfile.NamedTemporaryFile(suffix=".asc", delete=False) as tmp:
    tmp.write(detached_signature)
    sig_path = tmp.name
try:
    result = self._run(lambda: self._gpg.verify_data(sig_path, data))
finally:
    os.unlink(sig_path)
```

The `finally` block removes the file on normal exit and on Python exceptions. If the
process is killed with `SIGKILL` between file creation and `finally`, the `.asc` file
persists in `/tmp`. It contains the detached signature (not private key material) but
reveals that a verification occurred and the exact signature bytes. Default mode is
0600, so world-readability is not a concern on standard systems.

#### Mitigation

On Linux use `os.open(..., os.O_TMPFILE)` — the file has no directory entry and
disappears automatically when the fd is closed. On other platforms, document the
residual risk.

---

### L-5 — `psutil` Declared as Required Dependency but Never Imported *(Gemini finding #3 — confirmed)*

**File:** `src/gpg_meister/startup/environment_check.py:63`
**Status:** FIXED

Static analysis confirms `psutil` is never imported anywhere in `src/`. Its presence
in `_REQUIRED_PACKAGES` causes a hard `ERROR` startup warning if absent, potentially
blocking launch in minimal environments, with no functional benefit. Unnecessary
dependencies expand the supply-chain attack surface.

**Mitigation:** Remove `psutil` from `_REQUIRED_PACKAGES` and from `pyproject.toml`.

---

### L-6 — `_validate_text_payload` Restricts Sign/Verify to UTF-8; Decrypt Shows Binary as `repr`

**File:** `src/gpg_meister/services/message_service.py:203–209`
**Status:** Informational — no fix required

`sign()` and `verify()` correctly gate on UTF-8 input. `decrypt_view.py:133–135`
handles non-UTF-8 decrypted payloads by displaying `repr(result.plaintext)` — a
cosmetic quirk for binary GPG messages. `QTextEdit.setPlainText()` treats all content
as plain text with no HTML interpretation, so there is no injection risk within Qt.

---

## Chained Attack Scenarios

---

### Chain 1 — Key Smuggling → Keyring Pollution → Wrong-Recipient Encryption

**Exploitability:** Medium — requires delivering a crafted key blob to the victim

1. Attacker crafts a PGP public key blob:
   `[Bob's legitimate public key] ++ [attacker key with UID "Bob <bob@example.com>"]`
2. Alice imports "Bob's key" via `KeyService.import_armored()` or from a crafted vault
3. Due to H-1 / H-2: both keys enter Alice's keyring with no visible indication
4. Alice encrypts to "Bob" in the UI — if the attacker key is selected, plaintext goes
   to the attacker
5. Audit log records only FP_BOB (vault path) or both fingerprints (direct import) but
   either way Alice cannot distinguish the legitimate from the smuggled key

**Amplification:** If Alice creates a vault backup after the smuggled import, the
attacker key propagates inside the vault to any future recipient.

---

### Chain 2 — Crafted Vault → Silent Private Key Injection → Keyring Compromise

**Exploitability:** Medium — requires victim to open an attacker-supplied vault

1. Attacker creates a vault where `VaultKeyEntry.private_key_armored` for FP_ALICE
   contains Alice's real private key concatenated with the attacker's own private key
   in a single armored block
2. Alice opens the import wizard — the manifest lists only FP_ALICE, so she sees one
   entry and confirms import
3. `gpg.import_key(armored)` imports both keys at line 394
4. The `if entry.fingerprint in results` guard (H-1) returns and audits only FP_ALICE
   — attacker's private key is in Alice's keyring with zero audit trace
5. Any future vault export from Alice propagates the attacker's private key to other
   recipients

---

### Chain 3 — Factory Reset → Physical Recovery of Private Key Material

**Exploitability:** Low — requires physical disk access after reset

1. Alice's device is lost or stolen; she triggers factory reset
2. `perform_pending_factory_reset()` runs `shutil.rmtree()` — files are unlinked but
   not overwritten (M-3)
3. On SSD, `private-keys-v1.d/*.key` data persists in flash until block recycling
4. Attacker with physical access uses `photorec` / `testdisk` to recover key packets
5. If Alice's GPG passphrase is weak (or absent), the recovered private keys are
   immediately usable

---

### Chain 4 — Audit Hash Chain Bypass via Non-UTF-8 Log Corruption

**Exploitability:** Low — requires write access to the audit log file

1. Attacker gains write access to `audit.log` (permissions breach or disk access)
2. Attacker modifies a `key_imported` record by injecting non-UTF-8 bytes into a field
3. Both `_scan_for_last_hash` and `verify_chain` apply `errors="replace"` (M-4),
   computing hashes over the same U+FFFD-substituted form
4. The stored `prev_hash` in the following record was also computed over the garbled
   form at write time
5. `verify_chain()` agrees — chain passes despite the tampered record
6. The audit trail no longer accurately reflects what keys were imported

---

## Confirmed Clean Areas

The following modules were read in full and contain no security findings:

| Module | Notes |
|---|---|
| `security/aead.py` | ChaCha20-Poly1305 / AES-256-GCM; generic auth-fail error; key-length enforced |
| `security/kdf.py` | Argon2id; passphrase zeroed via `bytearray`; ctypes best-effort zero of raw KDF output |
| `security/secure_bytes.py` | `mlock` + `ctypes.memset`; pickle forbidden; re-entry guarded |
| `security/vault_format.py` | All length fields bounded; trailing-byte detection present |
| `security/password_policy.py` | NFKC normalisation; common-password blocklist |
| `startup/gpg_detector.py` | Whitelist enforced; root ownership required; parent-dir writability checked; inode pinning |
| `storage/permissions.py` | `_fchmod_nofollow` correct everywhere except C-1 |
| `storage/atomic_write.py` | `O_CREAT\|O_EXCL`; `fsync` before rename; parent `fsync` |
| `storage/file_lock.py` | `O_NOFOLLOW` on lock file; `reject_symlink` called |
| `storage/metadata_store.py` | All queries parameterised; WAL + `fchmod` sidecar protection |
| `storage/audit_log.py` | Whitelisted events; forbidden keys; hash chain on by default (modulo M-4) |
| `services/validation.py` | Strict allowlists for fingerprint / email / name / expiry; passphrase-in-argv check |
| `services/gpg_service.py` | `shell=False`; passphrase via `--passphrase-fd`; no user-controlled argv elements |
| `services/message_service.py` | Explicit `trust_confirmed` gate before `always_trust`; revoked/expired key checks |
| `models/vault.py` | Pydantic cross-field validation; `extra="forbid"`; length caps on all fields |
| `models/config.py` | `extra="forbid"`; `AuditConfig.hash_chain = True` by default |
| `models/kdf_params.py` | Import-time KDF caps prevent resource-DoS before authentication |
| `services/config_service.py` | Refuses world-writable config; atomically writes with mode 0o600 |
| `app.py` | `AuditLog` uses `config.audit.hash_chain`; chain verified at startup; hard exit on env errors |
| `ui/messages/decrypt_viewmodel.py` | Correct pattern: `del pp_str` applied after `SecureBytes` wrap |

---

## Priority Fix Table

| # | ID | File:line | Action |
|---|---|---|---|
| 1 | C-1 | `storage/log_config.py:161` | `os.fchmod(fh.fileno(), 0o600)` |
| 2 | H-1 | `services/vault_service.py:394–411` | Delete extra fingerprints post-import |
| 3 | H-2 | `services/key_service.py:236–244` | Move count gate before `import_key()` call |
| 4 | H-3 | `ui/vault/vault_import_view.py:143, 291` | Move both KDF/AEAD calls to Worker threads |
| 5 | M-4 | `storage/audit_log.py:228, 271` | Hash `raw` bytes, not re-encoded string |
| 6 | M-2 | All ViewModels | Apply `del pp_str` / `del pp_bytes` uniformly |
| 7 | M-3 | `storage/factory_reset.py:39–47` | Overwrite files before `rmtree` |
| 8 | M-6 | `storage/log_config.py:41–44` | Add `SECRET KEY BLOCK`; reconcile deny lists |
| 9 | M-5 | `ui/worker.py` | Ensure no passphrase bytes captured in closures (M-2 prerequisite) |
| 10 | M-7 | `services/config_service.py:38–43` | Escape U+0000–U+001F in TOML serialiser |
| 11 | L-1 | `ui/keys/first_launch_wizard.py:175` | Pass `trusted_sha256`; surface error to user |
| 12 | L-2 | `ui/clipboard.py` | Per-copy timer instead of singleton |
| 13 | L-3 | `storage/audit_log.py:96` | `pwd.getpwuid(os.geteuid()).pw_name` |
| 14 | L-4 | `services/gpg_service.py:449–459` | `O_TMPFILE` on Linux or document residual risk |
| 15 | L-5 | `startup/environment_check.py:63` | Remove `psutil` |

---

## Audit Methodology

- Full manual code review of all 35 Python source files in `src/gpg_meister/`
- Two independent passes: Gemini CLI (initial), Claude Sonnet 4.6 (deep — all files read)
- Attack surface coverage: subprocess injection, TOCTOU / symlink races, cryptographic
  correctness, passphrase lifetime in CPython heap, key smuggling, audit log integrity,
  factory reset completeness, memory forensics, chained attack construction
- Verification of all 1.0.2 security fixes against the current branch — no regressions found
- No fuzzing, dynamic analysis, or dependency vulnerability scanning performed
