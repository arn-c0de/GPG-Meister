# GPG Meister Codebase Quality Audit

Date: 2026-05-14
Scope: full local codebase review for quality-of-life fixes, readability,
refactoring, correctness, developer-loop health, UI responsiveness, security
hardening, and test reliability.

This file intentionally replaces the earlier accidental `planv2.md` edit. It is
a separate audit document and does not modify the project plan.

## 1. Current Quality Snapshot

The codebase is already structured into useful boundaries:

- `services/` owns GPG, key, message, vault, and config behavior.
- `security/` owns AEAD, KDF, secure bytes, vault framing, and password policy.
- `storage/` owns paths, metadata, audit, file locking, atomic writes, and
  permissions.
- `ui/` is split by feature area and mostly follows a View/ViewModel direction.
- Tests cover many security and service invariants.

The main quality issues are not lack of structure. They are drift between the
documented design and implementation, partial wiring of existing abstractions,
blocking UI paths, test hangs, and duplicated state/format knowledge.

Highest-risk areas:

- First-launch system keyring handling.
- Vault extension/format drift.
- Metadata lifecycle consistency.
- Startup environment checks.
- Qt modal dialogs in tests.
- Worker/threading state.
- Clipboard/security UX.
- Type boundaries between services, ViewModels, and tests.

## 2. P0: Correctness and Developer-Loop Fixes

### 2.1 Blocking Settings Test

The unit/security test run hangs. A timed run stopped at:

```text
tests/unit/test_settings_view.py::test_factory_reset_schedules_when_second_confirmation_matches
```

Root cause:

- The test patches `QMessageBox.warning` and `QInputDialog.getText`.
- `SettingsView._on_factory_reset_scheduled()` opens
  `QMessageBox.information`.
- In offscreen Qt this modal dialog blocks the test process.

Action:

- Patch `QMessageBox.information` in that test.
- Better: inject a small dialog/message adapter into `SettingsView` so tests can
  avoid real modal dialogs.
- Add pytest-level hang protection with `pytest-timeout`.

### 2.2 Ruff Failure

`ruff` currently reports one concrete error:

```text
src/gpg_meister/ui/messages/share_key_view.py:5
unused import: Qt
```

Action:

- Remove the unused `Qt` import.

### 2.3 Mypy Failures

`mypy` reports 43 errors. Most are not deep type-system problems. They mostly
come from concrete service types being required where tests pass fakes.

Common patterns:

- ViewModels require concrete `KeyService`, `MessageService`, `VaultService`
  instead of small Protocols.
- Qt parent types such as `QDialog` are not accepted where `QWidget | None` is
  declared.
- `setCurrentItem(None)` and similar Qt calls do not match strict stubs.

Action:

- Add service Protocols for the methods each ViewModel actually uses.
- Type UI parents as Qt expects.
- Isolate unavoidable Qt stub mismatches in tiny helpers instead of spreading
  ignores.

### 2.4 Integration Tests Fail on GPG Agent Startup

Integration tests fail during first real key generation:

```text
GPG did not return a fingerprint:
error running '/usr/bin/gpg-agent': exit status 2
```

Action:

- Treat integration tests as environment-sensitive.
- Add clearer skip/diagnostic output when `gpg-agent` cannot start.
- Keep unit/security tests separate from integration tests in CI.

## 3. Startup and Environment Check Bugs

### 3.1 `check_mlock()` Can False-Positive

`startup/environment_check.py` loads `"libc.so.6"` and can return true without
checking the `mlock()` return code.

Action:

- Use `ctypes.CDLL(None, use_errno=True)`.
- Check `res == 0`.
- Call `munlock()` only after successful `mlock()`.
- Surface errno in diagnostics.

### 3.2 Literal `{config_file}` Message

`check_config_permissions()` builds a warning with:

```text
Run: chmod 600 {config_file}
```

The placeholder is literal because that part is not an f-string.

Action:

- Fix the string interpolation.
- Add a unit test for the warning text.

### 3.3 Error Severity Is Collected as Warning

`CheckWarning(severity=ERROR)` is still collected in the warnings list and the
app opens the main window.

Action:

- Decide whether `ERROR` is fatal.
- If fatal, raise `EnvironmentCheckError`.
- If non-fatal, rename the severity to avoid a false guarantee.

### 3.4 Swap File Detection Is Incomplete

`_check_swap_linux()` only handles block devices under `/dev/...` and skips swap
files. A system using a swap file can be reported as encrypted/unknown instead
of unsafe.

Action:

- Include swap files from `/proc/swaps`.
- For files, inspect filesystem/device encryption if possible.
- Otherwise report "unknown" clearly instead of "OK".

## 4. Vault Format and Extension Drift

The project uses multiple vault extension/format identities:

- `security/vault_format.py`: `MAGIC = b"GPGV"`.
- `models/vault.py`: `VAULT_FORMAT_TAG = "GPGMEISTER_VAULT"`.
- `vault_export_view.py`: save dialog uses `*.gpgm` and auto-appends `.gpgm`.
- `vault_import_view.py`: import dialog uses `*.gpgm`.
- `vault_import_view.py`: checks first 16 bytes for `b"GPGMEISTER_VAULT"`,
  which does not match the actual frame starting with `b"GPGV"`.
- `help/glossary.py` and `help_view.py` mention `.gpgm`.
- `tests/integration/test_full_lifecycle.py` uses `.gpgm`.
- `tests/integration/test_vault_service.py` uses `.gpgvault`.
- Earlier plan text refers to `.gpgvault`.

Impact:

- A valid vault may be rejected by the import wizard's quick check.
- Users see inconsistent file extensions.
- Tests encode conflicting product decisions.

Action:

- Define one constant for extension and one constant for frame magic.
- Reuse those constants in UI, tests, docs, and services.
- Add tests for import wizard quick validation against a real vault frame.

## 5. First-Launch Wizard Critical Issue

`src/gpg_meister/ui/keys/first_launch_wizard.py` says it scans `~/.gnupg`
read-only. It constructs:

```python
GPGService(GPGServiceConfig(binary_path=self._binary, home_dir=_SYSTEM_GNUPG))
```

`GPGService.__init__()` always calls:

```python
ensure_dir(config.home_dir, mode=0o700)
```

`ensure_dir()` chmods existing POSIX directories. Therefore opening the
first-launch wizard can mutate the user's real `~/.gnupg` permissions, even
though the UI says the directory is not affected.

Additional issue:

- The wizard shows "Has private", but `_do_import()` exports/imports only public
  keys.

Action:

- Add a read-only `SystemGPGReader` or make `GPGService` opt into home-dir
  creation/chmod.
- Do not call `ensure_dir()` for the system keyring scan path.
- Clarify the wizard copy if only public keys are imported.
- Add a test that constructing/scanning system keyring does not chmod it.

## 6. Metadata Lifecycle Is Not Consistent

`MetadataStore` is used for labels, context, timestamps, and backup staleness.
Several service paths do not update it:

- `VaultService.create()` writes the vault and checksum but does not call
  `MetadataStore.add_vault_record()`.
- `KeyService.delete()` deletes from GPG but does not remove metadata rows.
- `KeyService.import_armored()` imports keys but does not upsert imported
  fingerprints.
- `KeyService.create()` writes metadata only when optional label/context values
  are provided.
- `app._on_key_created()` compensates for UI-created keys, but service behavior
  is not self-contained.

Impact:

- Backup staleness reminders can keep saying no vault backup exists after a
  vault was created through the UI.
- Deleted keys can leave stale labels/context in SQLite.
- Import timestamps are inconsistent.

Action:

- Decide whether services or the app layer own metadata writes.
- Prefer service ownership for key/vault lifecycle events.
- Add tests for create/import/delete/vault-create metadata side effects.

## 7. Audit Drift

`AuditConfig.enabled` exists, but production code constructs and uses `AuditLog`
regardless. The settings UI toggles hash-chain behavior, not audit emission.

Other drift:

- `AuditLog.ALLOWED_EVENTS` includes `config_loaded` and `config_saved`, but
  `ConfigService` does not emit these events.
- Encryption and verification are mostly not audited, while signing and
  decryption are.
- `AuditLog._check_payload()` checks only top-level payload keys. Nested payloads
  could contain sensitive names such as `password`, `secret`, or `private_key`.

Action:

- Wire `AuditConfig.enabled`, or remove/rename it.
- Align allowed events with real production events.
- Recursively scan payload dictionaries or enforce a flat typed payload schema.

## 8. Threading, Worker, and Storage Risks

### 8.1 MetadataStore Thread Safety Is Overstated

`MetadataStore` opens SQLite with `check_same_thread=False` and says concurrent
worker access is safe. There is no explicit lock around the shared connection.

Action:

- Add a `threading.RLock`, or use short-lived connections per operation.
- Add concurrent read/write tests if a shared connection remains.

### 8.2 Worker Loading State Can Race

ViewModels use boolean `loading_changed` with `QThreadPool.globalInstance()`.
Overlapping operations can emit `loading_changed(False)` while another operation
is still running.

Concrete example:

- `KeyListViewModel.request_delete()` starts delete and emits loading true.
- Delete success calls `refresh()`, which starts another worker.
- Delete worker `finished` emits loading false while refresh may still run.

Action:

- Track active operation count or operation tokens.
- Ignore stale load results when a newer load started.
- Add shutdown handling before closing `MetadataStore` and `AuditLog`.

### 8.3 Worker Errors Lose Context

`ui/worker.py` catches every exception and emits only `str(exc)`.

Missing:

- exception type
- traceback
- structured error code
- expected vs unexpected distinction

The project has `ui/errors/error_catalog.py`, but production code does not use
it.

Action:

- Emit a small `WorkerError` object.
- Map known errors through `error_catalog.py`.
- Log unexpected exceptions with traceback while showing safe UI text.

## 9. UI Responsiveness and MVVM Boundary Leaks

Several Views still call services directly or reach into ViewModel internals:

- `KeyListView._open_create_dialog`
- `KeyListView._open_import_dialog`
- `KeyListView._open_detail`
- direct use of `self._vm._svc`

Blocking UI paths:

- `VaultImportWizard` uses `QApplication.processEvents()` and synchronous
  decryption/import.
- `ShareKeyView._load_keys()` and `_on_key_selected()` call services
  synchronously.
- `KeyDetailView._copy_public_key()` and `_save_context()` call services
  synchronously.
- `FirstLaunchWizard.initializePage()` and `_do_import()` use GPG synchronously.
- `PublicKeyImportView` reads selected files directly into memory.

Action:

- Move service calls behind ViewModel methods.
- Use workers for GPG/vault/file operations.
- Keep Views responsible for rendering and user input only.

## 10. Clipboard Auto-Clear Is Mostly Not Wired

`AppConfig.clipboard_clear_seconds` is editable, but most copy actions call
`QApplication.clipboard().setText(...)` directly:

- message encrypt/sign/decrypt/share views
- GPG trust dialog SHA copy
- fingerprint label copy
- key detail public-key copy

`ClipboardButton` exists but is used only in `KeyDetailView`, and there it is
also connected to `_copy_public_key()` while its own text source is empty. It
also resets its label to `"Copy"`, losing custom labels like `"Copy Public Key"`.

Action:

- Route all copy actions through one clipboard helper/service.
- Pass `config.clipboard_clear_seconds` into that helper.
- Preserve original button labels after `"Copied!"`.
- Decide which copied values are sensitive and show one consistent warning.

## 11. Fingerprint UX

Several UI surfaces show only `fingerprint[-16:]`:

- key list tables
- first-launch wizard tables and confirmation page
- destructive confirmations
- import/export summaries

The recipient confirmation card is stronger because it shows a grouped full
fingerprint. The rest of the app should not train users to identify keys only by
a short suffix, especially in destructive or trust-sensitive flows.

Action:

- Keep short suffixes only as compact labels next to a full/copyable fingerprint.
- Use full grouped fingerprints in delete, export, import, share, and
  first-launch confirmation dialogs.
- Add a shared fingerprint display helper.

## 12. Config, Logging, and Permission Details

### 12.1 Config Assignment Validation

`AppConfig` uses `ConfigDict(extra="forbid")`, but not
`validate_assignment=True`. `SettingsViewModel` mutates `_pending` fields
directly.

Action:

- Enable assignment validation, or use `model_copy(update=...)` for changes.
- Add ViewModel tests that bypass widget constraints.

### 12.2 Config Directory Creation

`config_service.save()` uses:

```python
path.parent.mkdir(parents=True, exist_ok=True)
```

Startup normally calls `paths.ensure()`, but direct config saves can recreate the
directory using default umask permissions.

Action:

- Use `ensure_dir(path.parent, mode=0o700)` in `config_service.save()`.

### 12.3 Factory Reset Marker

`request_factory_reset()` writes the marker with `Path.write_text()`, not the
existing atomic write helper and not explicit `0600`.

Action:

- Use `atomic_write_bytes(..., mode=0o600)`.

### 12.4 Diagnostic Log File

`storage/log_config.py` opens the diagnostic log first and chmods it afterward.
With permissive umask, a new file can briefly exist with broader permissions.

Action:

- Use `os.open(..., mode=0o600)` and wrap with `os.fdopen()`.
- Keep chmod as repair for existing files.

### 12.5 Audit Actor Platform Assumption

`audit_log.py` falls back to `os.getuid()` when `USER` and `USERNAME` are
missing. `os.getuid()` is unavailable on Windows.

Action:

- Guard with `hasattr(os, "getuid")`.
- Fall back to `"unknown"` if no user identity exists.

## 13. File Lock and Vault Service Details

### 13.1 FileLock Documentation Mismatch

`storage/file_lock.py` says stale lock files are tolerated and removed when
acquiring the lock. The implementation does not remove stale files during
acquire; POSIX unlinks only on release.

Action:

- Implement stale-lock detection/removal, or update the docstring.
- Add tests for stale marker files.

### 13.2 Vault Import Subset Can Succeed With Zero Keys

`VaultService.import_keys()` accepts a fingerprint subset. If the caller passes
valid fingerprints not present in the manifest, the method can return success
with zero imported keys and audit `vault_imported`.

Action:

- Validate that every requested fingerprint exists in the manifest.
- Report missing fingerprints explicitly.
- Treat requested-zero-import as a failure unless the user selected no keys.

### 13.3 Vault Checksum Runs After Expensive Work

`VaultService._open()` validates the sidecar SHA-256 after reading/decrypting.
AEAD authentication is the authoritative integrity check, but if the checksum is
intended as a corruption precheck it runs too late.

Action:

- Verify the sidecar before KDF/decrypt, or document it as informational.

## 14. GPG and Crypto Boundaries

### 14.1 Duplicate Secret-Key Inventory

`GPGService.list_keys(secret=True)` calls `self._gpg.list_keys(secret=True)` and
then `_secret_fingerprints()`, which calls `list_keys(secret=True)` again.

Action:

- When `secret=True`, derive private-key status from the rows already loaded.
- Cache/optionalize the secret fingerprint lookup for public listings.

### 14.2 Secure Memory Boundaries

`security/aead.py` passes `bytes(key.view())` into PyCA APIs. That creates normal
Python `bytes` copies outside `SecureBytes`. `derive_key()` attempts to clear
immutable bytes via reassignment, which cannot zero the original allocation.

Action:

- Document this limitation near `SecureBytes`, `derive_key()`, and AEAD usage.
- Avoid implying all key material is locked/zeroized after third-party calls.
- Keep sensitive copies scoped tightly and delete references promptly.

### 14.3 Binary Signing Behavior

`GPGService.sign()` decodes bytes to string with surrogateescape before passing
data to `python-gnupg`. If binary signing is intended, this deserves explicit
tests.

Action:

- Decide whether signing is text-only or binary-safe.
- Add tests for non-UTF-8 bytes if binary support is intended.

## 15. i18n and Accessibility Drift

Translation resources exist, but production Python UI strings are plain literals.
Search found no meaningful use of:

- `self.tr(...)`
- `QCoreApplication.translate(...)`
- `translate(...)`

`scripts/build_translations.py` checks unfinished entries but does not extract
source strings.

Action:

- Either wire real Qt translation calls throughout UI code, or downgrade the
  documented i18n status.
- Add extraction/update workflow for `.ts` files.
- Keep user-facing strings centralized where possible.

## 16. Coverage, CI, and Packaging

### 16.1 Coverage Blind Spot

`pyproject.toml` omits all UI code from coverage:

```toml
omit = ["src/gpg_meister/ui/*"]
```

This hides modal dialogs, worker signal delivery, validation state, clipboard
behavior, and import/export flows.

Action:

- Stop omitting all UI after the modal hang is fixed.
- If full UI coverage is too noisy, omit only generated/purely visual files.
- Add targeted coverage for ViewModels, widgets, and dialog logic.

### 16.2 No GitHub Workflows

No `.github/workflows/` directory exists.

Action:

- Add CI for ruff, mypy, unit/security tests.
- Keep integration tests optional or environment-gated.
- Add package smoke checks later.

### 16.3 Version and Build Metadata Duplication

Version appears in:

- `pyproject.toml`
- `src/gpg_meister/__init__.py`
- `packaging/macos/setup.py`

Build scripts call `.venv/bin/...` directly while README commands use `uv run`.

Action:

- Make `pyproject.toml` the version source of truth.
- Replace direct `.venv/bin/...` calls with `uv run ...` where practical.
- Add a release check for version drift.

### 16.4 Packaging Gaps

Risk areas:

- Flatpak manifest uses `pip3 install --no-deps --prefix=/app .`; dependencies
  must be supplied elsewhere.
- AppImage script reuses the Windows PyInstaller spec.
- macOS setup hard-codes version `1.0.2`.

Action:

- Document dependency source for Flatpak.
- Split or rename platform-specific PyInstaller specs.
- Add smoke tests for built artifacts.

## 17. Large-File Refactor Targets

Largest source files observed:

- `services/gpg_service.py`: 429 lines
- `services/vault_service.py`: 412 lines
- `ui/messages/encrypt_view.py`: 390 lines
- `app.py`: 369 lines
- `ui/vault/vault_import_view.py`: 314 lines
- `ui/settings/settings_view.py`: 284 lines
- `ui/keys/key_list_view.py`: 269 lines

Line count alone is not a defect. The issue is mixed responsibilities:

- widget construction
- formatting helpers
- validation
- thread orchestration
- direct service calls
- user messaging

Action:

- Extract reusable UI components: key combo model, fingerprint formatter,
  recipient card, vault key table, clipboard command.
- Move common formatting helpers out of individual views.
- Split `app.py` dependency wiring once service Protocols exist.

## 18. Verification Commands Used

Commands run during the audit included:

```bash
env UV_CACHE_DIR=/tmp/uv-cache uv run ruff check .
env UV_CACHE_DIR=/tmp/uv-cache uv run mypy
timeout 45 env UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/unit tests/security -vv
env UV_CACHE_DIR=/tmp/uv-cache uv run pytest tests/integration -vv
rg "self.tr|QCoreApplication.translate|translate(" src/gpg_meister
rg "TODO|FIXME|XXX|HACK|processEvents|except Exception|QThread|Worker|clipboard" src tests
find src/gpg_meister -name "*.py" -print0 | xargs -0 wc -l | sort -nr | head -30
```

Notes:

- Full unit/security pytest run hangs because of the settings modal dialog.
- Integration tests fail in this environment because `gpg-agent` cannot start.
- `ruff` has one direct unused-import failure.
- `mypy` currently has 43 errors, mostly type-boundary issues.

## 19. Updated Top Priority List

1. Stop the first-launch wizard from chmoding or otherwise mutating `~/.gnupg`.
2. Fix the blocking settings test by patching/injecting `QMessageBox.information`.
3. Fix `check_mlock()` false positives and the literal `{config_file}` chmod message.
4. Unify vault extension/format constants across code, tests, docs, and help text.
5. Make metadata lifecycle updates explicit and consistent for keys and vaults.
6. Wire clipboard auto-clear through one helper and stop direct clipboard writes.
7. Fix Worker loading races before adding more background operations.
8. Remove the `ruff` unused import and fix the small direct `mypy` errors.
9. Introduce service Protocols and remove concrete-service typing from ViewModels/tests.
10. Stop Views from reaching into `viewmodel._svc`.
11. Convert synchronous View service calls to worker-backed ViewModel calls.
12. Activate real i18n or downgrade the documented i18n status.
13. Add pytest timeout protection after the known modal hang is fixed.
14. Add CI for ruff, mypy, unit/security tests, and optional integration tests.

