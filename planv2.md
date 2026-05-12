# GPG Meister — Implementation Plan v2

## 1. Purpose and Scope

GPG Meister is a local-first desktop application for GPG key management, message
encryption/decryption, and encrypted key vault backup/transfer. It runs entirely on the
user's machine. No server is involved. Private keys never leave the device unencrypted.

This document supersedes `secure_gpg_tool_architecture.md` and records all design
decisions made after evaluating current (2026) best practices for Python desktop
applications, cryptographic libraries, project tooling, and secure memory handling.

---

## 2. Key Design Decisions

### 2.1 GUI Framework — PySide6 (not Tkinter)

**Decision:** Replace Tkinter with **PySide6**.

**Rationale:**
- Tkinter is functional but produces visually dated interfaces and has no built-in support
  for theming, data-binding, or model/view separation.
- PySide6 is the officially supported Qt Python binding under the **LGPL**, allowing
  open-source and future proprietary distribution without requiring a commercial license.
- Qt's signal/slot system maps cleanly to an MVVM architecture.
- Qt provides native OS look-and-feel on Windows, Linux, and macOS.
- PySide6 ships with Qt Designer for optional visual layout editing.

**Rejected alternatives:**
- PyQt6: Identical API to PySide6 but GPL-licensed — requires open-source distribution.
- CustomTkinter: Better than plain Tkinter but limited for complex layouts and has no
  established architecture pattern.
- Tkinter: Retained only if PySide6 proves unavailable in a specific packaging target.

---

### 2.2 Architecture Pattern — MVVM

**Decision:** Use Model-View-ViewModel (MVVM) pattern throughout the UI layer.

**Rationale:**
- The security rule "UI must not contain cryptographic logic" maps exactly to MVVM's
  separation: Views hold widgets only, ViewModels hold UI state and call services,
  Models represent domain data.
- Qt's `QProperty`, signals, and slots provide native data-binding infrastructure.
- ViewModels can be unit-tested without instantiating any Qt widget.

**Layer responsibilities:**

```
View         PySide6 widgets. Zero business logic. Binds to ViewModel signals.
ViewModel    UI state, input validation, calls to service layer, result formatting.
Model        Immutable domain objects (Pydantic v2 dataclasses).
Service      Cryptographic and GPG operations. No Qt dependency.
```

---

### 2.3 GPG Integration — python-gnupg (vsajip)

**Decision:** Use `python-gnupg` (maintained by Vinay Sajip, PyPI: `python-gnupg`).

**Rationale:**
- The most actively maintained Python wrapper for the local GnuPG binary.
- Communicates with the GPG process via subprocess without `shell=True`, avoiding
  shell-injection vulnerabilities that affected earlier versions.
- No shared library version-pinning problem (unlike the official GPGME C bindings, which
  must match the installed GnuPG version exactly to avoid crashes).
- All user-supplied strings passed to GPG must be validated before use (fingerprint
  format, email format, key type enum) — enforced at the ViewModel boundary.

**Rejected alternatives:**
- `pygpgme`: Unmaintained since 2013.
- Official GPGME Python bindings: Version-coupling makes packaging fragile.
- Raw subprocess: Requires re-implementing everything python-gnupg already handles safely.

---

### 2.4 Vault Encryption — ChaCha20-Poly1305 (primary)

**Decision:** Use **ChaCha20-Poly1305** as the primary vault cipher, with **AES-256-GCM**
as a configurable alternative.

**Rationale:**
- Both are AEAD ciphers providing confidentiality, integrity, and authenticity.
- ChaCha20-Poly1305 is resistant to timing side-channels caused by AES cache-timing
  attacks in software (relevant on hardware without AES-NI, e.g., older or embedded CPUs).
- RFC 8439 standardizes ChaCha20-Poly1305. It is used in TLS 1.3 and WireGuard.
- The `cryptography` library (PyCA) implements both under `cryptography.hazmat.primitives.aead`.
- The vault header records which cipher was used, enabling future migration.

**Nonce rules:**
- Generate a fresh 96-bit (12-byte) random nonce per vault write.
- Never reuse a nonce with the same derived key.
- The nonce is stored in the vault header (not secret).

---

### 2.5 Key Derivation — Argon2id

**Decision:** Use **Argon2id** via `argon2-cffi` (PyPI: `argon2-cffi`).

**Rationale:**
- Argon2id is the RFC 9106 recommended variant; it combines resistance to GPU attacks
  (from Argon2d) and side-channel resistance (from Argon2i).
- `argon2-cffi` version 25.1.0 ships `argon2.profiles.RFC_9106_HIGH_MEMORY` as a
  ready-made parameter set for high-security one-time operations such as vault creation.

**Default parameters for vault derivation (high-memory profile):**

| Parameter    | Value      | Justification                          |
|--------------|------------|----------------------------------------|
| time_cost    | 3          | RFC 9106 recommendation                |
| memory_cost  | 262144 KB  | 256 MB — makes GPU attacks expensive   |
| parallelism  | 4          | Matches RFC_9106_HIGH_MEMORY profile   |
| hash_len     | 32 bytes   | 256-bit key for ChaCha20/AES-256       |
| salt_len     | 16 bytes   | 128-bit random salt per vault          |

**Adaptive parameter strategy:**
- The high-memory profile is the default and must always be used when ≥ 1.5 GB free RAM
  is available (checked via `psutil.virtual_memory().available`).
- On low-memory hardware (e.g., 4 GB total RAM), the application offers a **balanced
  profile** (`time_cost=4`, `memory_cost=65536 KB / 64 MB`, `parallelism=4`) and requires
  the user to acknowledge the reduced GPU-resistance in a one-time dialog.
- On first launch, the app benchmarks the chosen profile (`kdf.benchmark_params`). If
  derivation takes < 200 ms, it warns the user that parameters may be too weak for the
  hardware (CPU underused) and suggests increasing `time_cost`.
- The minimum policy floor (refused regardless of override): `time_cost >= 2`,
  `memory_cost >= 19456 KB / 19 MB` (RFC 9106 lower bound), `hash_len == 32`,
  `salt_len >= 16`. Anything below is rejected by `kdf.derive_key`.
- Selected parameters are written to the vault header and authenticated via AAD
  (see §4.2, §6.1) so they cannot be downgraded by an attacker tampering with the file.

---

### 2.6 Domain Models — Pydantic v2

**Decision:** Use **Pydantic v2** (`pydantic`) for all domain models.

**Rationale:**
- Provides runtime validation, strict type enforcement, and clean serialization.
- Immutable models (`model_config = ConfigDict(frozen=True)`) prevent accidental mutation
  of key data throughout service calls.
- Pydantic v2 is 5–50x faster than v1 (Rust core).
- Replaces manual validation scattered across service methods.

**Models:**
- `KeyInfo` — fingerprint, user IDs, key type, length, creation/expiry, trust, revocation
- `VaultHeader` — format tag, version, KDF params, cipher params, timestamps
- `VaultManifest` — created_by, description, list of `VaultKeyEntry`
- `VaultKeyEntry` — fingerprint, user IDs, armored public + optional armored private key
- `EncryptResult` — armored ciphertext, signing fingerprint, timestamp
- `DecryptResult` — plaintext bytes, signer fingerprint, validity flags
- `AppConfig` — all non-secret application settings

All models that may carry sensitive fields (e.g., `VaultKeyEntry.private_key_armored`)
implement a custom `__repr__` and `__str__` that redact the field, preventing accidental
log exposure.

---

### 2.7 Vault File Format

**Decision:** Binary-framed file with a JSON header block and a msgpack-serialized
encrypted payload.

**Rationale:**
- JSON header is human-inspectable without a special tool — useful for debugging a
  corrupted vault without decrypting it.
- msgpack for the payload is compact, binary-safe, and avoids the security risks of
  pickle. It has no execution semantics (unlike pickle) and is well-supported.
- The entire structure is length-prefixed so parsers can detect truncation.

**File layout:**

```
[4 bytes]  Magic: b"GPGV"
[1 byte ]  Major version: 0x02
[4 bytes]  Header length (big-endian uint32)
[N bytes]  Header JSON (UTF-8, no secrets)
[4 bytes]  Payload length (big-endian uint32)
[M bytes]  Encrypted payload (ChaCha20-Poly1305 or AES-256-GCM ciphertext + tag)
```

The GCM/Poly1305 authentication tag is appended by the `cryptography` library to the
ciphertext. A corrupted payload is detected without the passphrase because the AEAD tag
covers the entire payload.

**File extension:** `.gpgvault`
**Checksum sidecar:** `.gpgvault.sha256` (SHA-256 of the entire `.gpgvault` file)

---

### 2.8 Project Tooling — uv + ruff + mypy

**Decision:** Use `pyproject.toml` as the single configuration file.
Use `uv` for dependency management, `ruff` for linting/formatting, `mypy` in strict mode
for type checking.

**Rationale:**
- `uv` (Astral) resolves and installs dependencies 10–100x faster than pip/Poetry and
  generates a locked `uv.lock` file for reproducible builds.
- `ruff` replaces flake8, isort, pyupgrade, and bandit (partial) in a single tool that
  runs in milliseconds.
- `mypy --strict` catches type errors at development time, not at runtime in production.
- A single `pyproject.toml` replaces `setup.py`, `setup.cfg`, `requirements.txt`,
  `.flake8`, and `mypy.ini`.

**Minimum Python version:** 3.11 (required for `tomllib`, `ExceptionGroup`, and
performance improvements to dataclasses).

---

### 2.9 Storage Paths — XDG Base Directory Specification

**Decision:** Follow the XDG Base Directory Specification on Linux/macOS. Use
`%APPDATA%\GPGMeister` on Windows.

**Rationale:**
- Storing data under `./data/` relative to the executable is not appropriate for installed
  applications and causes permission issues on multi-user systems.
- XDG standard:
  - Config: `$XDG_CONFIG_HOME/gpg-meister/` (default: `~/.config/gpg-meister/`)
  - Data:   `$XDG_DATA_HOME/gpg-meister/`   (default: `~/.local/share/gpg-meister/`)
  - Logs:   `$XDG_STATE_HOME/gpg-meister/`  (default: `~/.local/state/gpg-meister/`)
- The GPG home directory used by the application lives inside the data directory:
  `$XDG_DATA_HOME/gpg-meister/gnupg/`

---

### 2.10 Structured Logging — structlog

**Decision:** Use `structlog` for all application logging.

**Rationale:**
- structlog provides structured key-value log output (JSON in production, colored in dev).
- A `SensitiveDataFilter` processor (see §5.4) strips known sensitive payloads before the
  log entry is emitted.
- This is safer than relying on developers to manually avoid logging secrets.

---

### 2.11 Audit Logging (separate channel)

**Decision:** Maintain a dedicated audit log, strictly separated from the debug/diagnostic
log defined in §2.10.

**Rationale:**
- Cryptographic operations must produce a tamper-evident record independent of debug
  verbosity. Mixing audit events into the same sink as debug logs risks accidental
  deletion, rotation, or suppression.
- Operators and forensic analysts need a stable, append-only stream containing only
  security-relevant events.

**Implementation:**
- Separate `structlog` logger named `audit` with its own processor chain and sink:
  `$XDG_STATE_HOME/gpg-meister/audit.log` (mode 0600, append-only).
- Logs exclusively the following events: `key_generated`, `key_deleted`,
  `key_exported_public`, `key_exported_private`, `vault_created`, `vault_imported`,
  `vault_import_failed`, `message_signed`, `message_decrypted`, `message_decrypt_failed`,
  `gpg_binary_resolved`, `startup_environment_check`.
- Each entry contains: ISO 8601 UTC timestamp, event name, actor (OS user), fingerprint(s)
  involved, outcome (`ok` / `failed`), and reason on failure.
- **Never** contains key material, passphrases, plaintext, or ciphertext.
- Optional hash-chain mode: each record includes SHA-256 of the previous record as
  `prev_hash`, enabling cheap tamper detection. Enabled via `AppConfig.audit.hash_chain`.
- The debug logger's processor chain explicitly excludes audit event names; the audit
  logger's chain forbids unstructured `info()`/`debug()` calls (lint rule + runtime
  assertion in `storage/log_config.py`).

---

## 3. Project Structure

```
gpg-meister/
│
├── pyproject.toml              Single config: uv, ruff, mypy, pytest, coverage
├── uv.lock                     Pinned dependency tree (commit to VCS)
├── README.md
│
├── src/
│   └── gpg_meister/
│       ├── __init__.py
│       ├── app.py              Entry point: creates QApplication, wires dependencies
│       │
│       ├── models/             Pydantic v2 domain objects (no logic)
│       │   ├── __init__.py
│       │   ├── key_info.py
│       │   ├── vault.py        VaultHeader, VaultManifest, VaultKeyEntry
│       │   ├── message.py      EncryptResult, DecryptResult, SignResult, VerifyResult
│       │   └── config.py       AppConfig
│       │
│       ├── services/           Pure Python, no Qt dependency
│       │   ├── __init__.py
│       │   ├── gpg_service.py       Thin wrapper over python-gnupg
│       │   ├── key_service.py       Key lifecycle logic
│       │   ├── message_service.py   Encrypt / decrypt / sign / verify
│       │   ├── vault_service.py     Vault create / open / verify
│       │   └── config_service.py    Load, validate, persist AppConfig
│       │
│       ├── security/           Cryptographic primitives (no Qt, no GPG dependency)
│       │   ├── __init__.py
│       │   ├── kdf.py               Argon2id derivation, parameter validation
│       │   ├── aead.py              ChaCha20-Poly1305 / AES-256-GCM encrypt/decrypt
│       │   ├── vault_format.py      Vault binary frame: pack / unpack / validate magic
│       │   ├── password_policy.py   Strength checks, common-password rejection
│       │   ├── secure_bytes.py      SecureBytes context manager (zero-on-exit)
│       │   └── integrity.py         SHA-256 checksum helpers
│       │
│       ├── storage/            File system and database access
│       │   ├── __init__.py
│       │   ├── paths.py             XDG-aware path resolution
│       │   ├── permissions.py       Unix 700/600 enforcement, Windows ACL helpers
│       │   ├── atomic_write.py      tmp+replace+fsync helper for vault & sidecar
│       │   ├── file_lock.py         flock / msvcrt.locking cross-platform wrapper
│       │   ├── metadata_store.py    SQLite via sqlite3 (no ORM needed)
│       │   ├── log_config.py        structlog setup, sensitive-data filter
│       │   └── audit_log.py         Separate audit logger, optional hash chain
│       │
│       ├── i18n/                Translation sources (.ts) + compiled .qm
│       │   ├── __init__.py
│       │   ├── en.ts
│       │   ├── de.ts
│       │   ├── terms_en.md          Canonical English glossary for translators
│       │   └── terms_de.md          Canonical German glossary for translators
│       │
│       ├── ui/                 PySide6 — views and viewmodels only
│       │   ├── __init__.py
│       │   ├── main_window.py       QMainWindow, tab bar, startup checks
│       │   │
│       │   ├── errors/
│       │   │   ├── user_error.py    UserError dataclass (code, args, severity)
│       │   │   └── error_catalog.py Internal-error → catalog-entry mapping (§14.1)
│       │   │
│       │   ├── help/
│       │   │   ├── help_view.py     Help tab with sections + glossary
│       │   │   └── glossary.py      Term → definition map, used by ? icons

│       │   │
│       │   ├── keys/
│       │   │   ├── key_list_view.py
│       │   │   ├── key_list_viewmodel.py
│       │   │   ├── key_create_view.py
│       │   │   ├── key_create_viewmodel.py
│       │   │   ├── key_detail_view.py
│       │   │   └── public_key_import_view.py
│       │   │
│       │   ├── messages/
│       │   │   ├── encrypt_view.py
│       │   │   ├── encrypt_viewmodel.py
│       │   │   ├── decrypt_view.py
│       │   │   ├── decrypt_viewmodel.py
│       │   │   ├── sign_view.py
│       │   │   └── verify_view.py
│       │   │
│       │   ├── vault/
│       │   │   ├── vault_export_view.py
│       │   │   ├── vault_export_viewmodel.py
│       │   │   ├── vault_import_view.py
│       │   │   └── vault_import_viewmodel.py
│       │   │
│       │   ├── settings/
│       │   │   ├── settings_view.py
│       │   │   └── settings_viewmodel.py
│       │   │
│       │   └── widgets/        Reusable custom widgets
│       │       ├── passphrase_field.py    Masked input + strength indicator
│       │       ├── fingerprint_label.py   Monospace, copyable
│       │       ├── warning_banner.py      Prominent risk warnings
│       │       └── clipboard_button.py    Copy + auto-clear timer
│       │
│       └── startup/
│           ├── __init__.py
│           ├── gpg_detector.py      Locate and validate GPG binary at startup
│           └── environment_check.py Permissions, directories, Python packages
│
└── tests/
    ├── conftest.py              Shared fixtures: temp GPG home, test keys
    ├── unit/
    │   ├── test_kdf.py
    │   ├── test_aead.py
    │   ├── test_vault_format.py
    │   ├── test_password_policy.py
    │   ├── test_key_service.py
    │   ├── test_message_service.py
    │   └── test_config_service.py
    ├── integration/
    │   ├── test_gpg_service.py       Requires installed GnuPG
    │   ├── test_vault_roundtrip.py
    │   └── test_key_lifecycle.py
    └── security/
        ├── test_wrong_passphrase.py
        ├── test_vault_tamper.py
        ├── test_log_sanitization.py
        └── test_no_temp_plaintext.py
```

---

## 4. Module Responsibilities

### 4.1 `security/kdf.py`

Single responsibility: derive a fixed-length key from a passphrase using Argon2id.

Interface:
- `derive_key(passphrase: SecureBytes, salt: bytes, params: KDFParams) -> SecureBytes`
- `generate_salt() -> bytes`
- `default_params() -> KDFParams` — returns RFC_9106_HIGH_MEMORY parameters
- `benchmark_params(params: KDFParams) -> float` — measures derivation time in ms

`KDFParams` is a frozen Pydantic model holding `time_cost`, `memory_cost`, `parallelism`,
`hash_len`, `salt_len`.

Raises `KDFError` (a custom exception) on failure. Never raises a raw `Exception`.

---

### 4.2 `security/aead.py`

Single responsibility: AEAD encrypt and decrypt bytes with associated data.

Interface:
- `encrypt(plaintext: bytes, key: SecureBytes, nonce: bytes, associated_data: bytes, cipher: CipherChoice) -> bytes`
- `decrypt(ciphertext: bytes, key: SecureBytes, nonce: bytes, associated_data: bytes, cipher: CipherChoice) -> bytes`
- `generate_nonce() -> bytes`
- `CipherChoice` — enum with `CHACHA20_POLY1305` and `AES_256_GCM`

**Associated data:** The caller (vault_service) passes the canonical byte representation
of the vault header (UTF-8 JSON bytes as written to disk) as `associated_data`. This
binds the header — including KDF parameters, cipher choice, and nonce — to the
authentication tag. Any tampering with header fields (e.g., downgrading `time_cost`)
causes decryption to fail with `DecryptionError` rather than silently producing wrong
plaintext or being detected only via key-derivation mismatch.

An incorrect key, tampered ciphertext, or tampered header raises `DecryptionError`
(wraps `cryptography.exceptions.InvalidTag`). The caller sees a single error type, not
internal library details, and the error message does not distinguish between cause
(passphrase vs. ciphertext vs. header).

---

### 4.3 `security/vault_format.py`

Single responsibility: serialize and deserialize the binary vault frame.

Interface:
- `pack(header: VaultHeader, ciphertext: bytes) -> bytes`
- `unpack(data: bytes) -> tuple[VaultHeader, bytes]`

`unpack` validates the magic bytes, version, and length fields before touching the header
JSON. Returns `VaultFormatError` on any structural mismatch. The passphrase is not
involved here — this layer only handles the binary container.

---

### 4.4 `security/secure_bytes.py`

A context-manager wrapper for bytes that holds passphrase or key material.

Behaviour:
- Exposes the underlying bytes only while inside the `with` block.
- On `__exit__`, overwrites the internal buffer with zeros using `ctypes.memset`.
- Prevents the value from appearing in `repr()`, `str()`, or pickling.
- On Linux/macOS, calls `mlock()` on the underlying buffer via ctypes to prevent
  the OS from paging the memory to disk.

Limitation documented explicitly: Python's garbage collector may copy bytes internally
before the explicit zero-fill. This cannot be fully prevented in CPython. The architecture
minimises the window by keeping `SecureBytes` objects short-lived.

---

### 4.5 `services/gpg_service.py`

Thin adapter over `python-gnupg`. All inputs are validated before being passed to GPG.

**Validation rules enforced before calling python-gnupg:**
- Fingerprints: uppercase hex, exactly 40 characters (regex `^[0-9A-F]{40}$`).
- Email addresses: RFC 5321 basic format check.
- Key type: enum (`RSA`, `ECDSA`, `EDDSA`, `ECDH`), not a free string.
- Key length: validated against an allow-list per type:
  - RSA: `{2048, 3072, 4096}`
  - ECDSA (NIST curves): `{256, 384, 521}`
  - EdDSA: `{255}` (Ed25519)
  - ECDH (encryption subkey for EdDSA primary): `{255}` (Curve25519/cv25519)
- Expiry: ISO 8601 date OR relative offset matching `^[1-9][0-9]*[ymwd]$` (positive only).
- File paths passed to GPG (e.g., for `--import` of a public key file) are absolute and
  validated to live inside the application's data directory or an explicitly
  user-selected path — never derived from user-controlled raw strings.

**Subprocess hardening:**
- `shell=False` always (python-gnupg default — verified by an assertion).
- Passphrases are passed **only** via stdin/file descriptor (`--passphrase-fd`),
  never as CLI argument — see §5.6.
- `--batch --pinentry-mode loopback` is required so that GPG does not spawn an external
  Pinentry process (which would block the application). The loopback mode causes GPG to
  read the passphrase from the configured fd, matching python-gnupg's expectations.
- The GPG home directory is always explicitly set via `--homedir`, never relying on
  `$GNUPGHOME` or the user default.
- Stdout/stderr are captured and parsed structurally; no shell redirection.

All python-gnupg result objects are translated to domain models before being returned to
callers. No python-gnupg types leak past this module.

---

### 4.6 `services/vault_service.py`

Orchestrates vault creation and import. Calls `kdf.py`, `aead.py`, `vault_format.py`,
and `gpg_service.py`.

**Export flow (in-memory only, no temp plaintext files):**
1. Acquire an exclusive advisory file lock on the target path's directory
   (`fcntl.flock` on POSIX, `msvcrt.locking` on Windows) to prevent concurrent vault
   writes from another app instance. Release in `finally`.
2. Accept selected fingerprints and master passphrase as `SecureBytes`.
3. Export private key material as armored strings via `gpg_service.py`. Each export
   produces a `key_exported_private` audit event (§2.11).
4. Assemble `VaultManifest` in memory (includes `created_at`, `app_version`,
   `created_by`).
5. Serialize manifest to msgpack bytes.
6. Generate fresh 16-byte salt and 12-byte nonce.
7. Build header JSON (KDF params, cipher params — no timestamps, no app version; see §6.2)
   and serialize to canonical UTF-8 bytes.
8. Derive vault key with Argon2id from passphrase + salt.
9. Encrypt msgpack bytes with ChaCha20-Poly1305, passing the header bytes as
   `associated_data` (binds the header to the AEAD tag — see §4.2).
10. Pack into vault binary frame via `vault_format.pack`.
11. **Atomic write:** write frame to `<target>.tmp` in the same directory with mode 0600,
    `fsync()` the file descriptor, then `os.replace(<target>.tmp, <target>)`. Finally
    `fsync()` the parent directory. This guarantees that no partially-written vault is
    ever observable at the target path.
12. Compute SHA-256 of the final frame; write checksum sidecar via the same
    tmp+replace+fsync sequence.
13. Emit `vault_created` audit event with target path, fingerprint count, cipher choice.
14. Zero all intermediate sensitive variables using `SecureBytes`.

**Import flow:**
1. Acquire shared advisory lock on the source path.
2. Read vault file.
3. Unpack binary frame via `vault_format.unpack` — validates magic, version, lengths.
4. Recompute SHA-256 and compare against sidecar (if present). Mismatch produces a
   loud warning before attempting decryption; user must confirm to proceed.
5. Accept master passphrase as `SecureBytes`.
6. Derive vault key using KDF parameters read from the header. The same canonical
   header bytes are reconstructed from the parsed header (or, more safely, the original
   header byte slice is retained from `unpack`) for use as AAD.
7. Decrypt payload with `associated_data = header_bytes`. Failure raises
   `DecryptionError` with a generic message — no distinction between wrong passphrase,
   tampered ciphertext, or tampered header. Emit `vault_import_failed` audit event.
8. Deserialize msgpack to `VaultManifest`.
9. Present key fingerprints to the caller (ViewModel).
10. Import selected keys via `gpg_service.py`. Each import produces a `key_imported`
    audit event.
11. Emit `vault_imported` audit event.
12. Zero all sensitive intermediates.

---

### 4.7 `storage/metadata_store.py`

Uses Python's built-in `sqlite3` module. No ORM.

Tables:
- `key_metadata`: fingerprint, label, import_timestamp, last_used_timestamp
- `vault_record`: filename, creation_timestamp, key_count, description
- `app_preferences`: key, value (non-sensitive UI preferences only)

Constraints:
- No private keys, passphrases, or decrypted content stored here.
- All timestamps stored as UTC ISO 8601 strings.

---

### 4.8 `ui/` ViewModel Contract

Each ViewModel:
- Inherits from `QObject`.
- Exposes state as `QProperty` or `Signal` — no direct widget references.
- Calls services via injected interfaces (dependency injection, not global singletons).
- Emits typed result signals: `operation_succeeded = Signal(object)`,
  `operation_failed = Signal(str)`.
- Never holds `SecureBytes` longer than the operation that needs it.
- All service calls that may block run in a `QThreadPool` worker to avoid freezing the UI.

Each View:
- Inherits from the appropriate Qt widget class.
- Receives its ViewModel via constructor injection.
- Only connects signals and slots — no conditional logic, no data transformation.
- Clears sensitive text fields after the operation completes or on explicit user action.

---

## 5. Security Model

### 5.1 Two-Layer Passphrase Model

```
Layer 1 — GPG passphrase
  Protects each private key in the local GPG keyring.
  Handled entirely by GnuPG. The application passes it through python-gnupg only during
  key creation, decryption, and signing operations. It is not stored anywhere.

Layer 2 — Vault master passphrase
  Protects the vault file during backup and transfer.
  Derived via Argon2id into a temporary vault key.
  The vault key exists in memory only during vault encrypt/decrypt operations.
  It is zero-filled immediately after use via SecureBytes.__exit__.
```

### 5.2 Private Key Handling Rules

- Private keys are never written to disk in plaintext by this application.
- The only path from a private key to disk is: export to armored string in memory →
  include in vault manifest in memory → encrypt → write ciphertext to disk.
- Private key export is always preceded by a modal warning dialog that names the
  fingerprint and explains the risk.
- Private key export for vault creation does not create a temporary file — the armored
  string is held in a `SecureBytes` instance in memory.

### 5.3 Clipboard Policy

- Copying a private key armored block or decrypted message plaintext triggers a warning
  banner in the UI.
- A configurable auto-clear timer (default: 60 seconds) clears the system clipboard
  after a sensitive copy operation.
- The clipboard clear is best-effort: it is cancelled if the clipboard content changes
  before the timer fires (to avoid clearing content the user pasted from elsewhere).

### 5.4 Log Sanitization

- `structlog` pipeline includes a `SensitiveDataFilter` processor inserted before the
  renderer.
- The filter operates **primarily by key-name allow/deny lists**, not heuristic content
  scanning, to avoid false negatives (a secret in an unexpected key) and false positives
  (a long base64 logo or hash):
  - **Deny-list (always redacted, regardless of content type):** any log key whose name
    matches `passphrase`, `password`, `secret`, `private_key`, `armored_private`,
    `plaintext`, `decrypted`, `vault_key`, `derived_key`, `salt` (when paired with a
    passphrase context), `pin`, `token`.
  - **Content-based redaction (defence-in-depth):** any string value that contains the
    substring `-----BEGIN PGP PRIVATE KEY BLOCK-----` or `-----BEGIN PGP MESSAGE-----`
    is redacted regardless of key name.
  - **Allow-list for known-safe long strings:** fields explicitly tagged as safe
    (e.g., `fingerprint`, `sha256`, `magic_bytes`) are exempt from the base64 heuristic.
- The base64-length heuristic of v1 (any base64 > 80 chars) is **removed** in v2 because
  it produced false positives on legitimate fingerprint chains, file hashes, and
  embedded logos.
- Raw exception tracebacks are not shown in the production UI. They are written to the
  log file only after passing through the filter. Exception messages are run through
  the redactor before being formatted.
- The audit logger (§2.11) uses a separate, stricter chain: it asserts at runtime that
  no record contains any key from the deny-list above and fails closed (drops the record
  + logs to debug) if violated.

### 5.5 Startup Security Checks

On every launch, in order:

1. Locate GPG binary (see §9.2 path resolution and whitelist).
2. Verify GPG version >= 2.2.0 (hard fail). Warn if < 2.4.0 (no Kyber/PQC subkey
   support).
3. Verify GPG home directory exists with permissions 0700 (create if absent).
4. Verify vault directory exists with permissions 0700 (create if absent).
5. Verify config file permissions: refuse to start if world-readable on POSIX; warn if
   group-readable.
6. Verify all required Python packages are importable.
7. Check if `mlock` is available on this platform (info log + audit event only, not a
   hard failure).
8. **Swap encryption check** (informational, not a hard failure):
   - Linux: parse `/proc/swaps`; for each swap device, resolve the underlying block
     device and check whether it is a dm-crypt mapping (path starts with `/dev/mapper/`
     and is listed in `/proc/crypto` or referenced from `/etc/crypttab`). If any swap
     entry is unencrypted, raise a non-blocking warning banner in the main window
     recommending `swapoff` or dm-crypt configuration.
   - macOS: run `fdesetup status`; if FileVault is off, warn (FileVault encrypts the
     swap partition).
   - Windows: warn unconditionally that page-file contents are not encrypted unless
     BitLocker protects the system volume. Optionally probe BitLocker status via
     `manage-bde -status` if available and the user has elevated rights.
   - The result is recorded as a `startup_environment_check` audit event with field
     `swap_encrypted: bool | unknown`.
9. Sanity-check the GPG binary's ownership on POSIX (`stat().st_uid == 0`) when it
   resides in the whitelisted standard paths; deviations from this are surfaced as a
   warning but not a hard failure, since some package managers install under non-root.

Any hard failure (GPG not found, GPG version too old, whitelisted path tampered with
without user override) shows a blocking error dialog and prevents the application from
opening.

---

### 5.6 Passphrase Transport

- Passphrases (both the user's GPG passphrase and the vault master passphrase) are
  represented at runtime by `SecureBytes` (§4.4) and never converted to `str` in
  application code, since `str` cannot be reliably zeroed in CPython.
- When invoking GPG, passphrases are passed exclusively via a file descriptor
  (`--passphrase-fd <n>`) with the passphrase bytes written to that fd by the subprocess
  driver. They never appear:
  - As a command-line argument (would be visible in `/proc/<pid>/cmdline` and `ps`).
  - In an environment variable (would be visible in `/proc/<pid>/environ`).
  - In a temporary file on disk.
- `gpg_service.py` includes a runtime assertion that no element of the constructed
  argv contains the passphrase bytes, and a test (`test_passphrase_not_in_argv`) that
  verifies this invariant for every code path that supplies a passphrase to GPG.
- `--pinentry-mode loopback` is required so GPG reads from the configured fd instead
  of invoking an external Pinentry agent (which would not receive our passphrase and
  would block the subprocess waiting for terminal input).
- Once the operation returns, the `SecureBytes` `__exit__` zeroes the buffer. The
  caller must use the `with` statement; lint rule + runtime check enforces this.

---

## 6. Vault File Specification

### 6.1 Binary Frame

```
Offset  Size    Field
0       4       Magic bytes: 0x47 0x50 0x47 0x56  ("GPGV")
4       1       Major format version: 0x02
5       4       Header JSON length, big-endian uint32
9       N       Header JSON, UTF-8  (bytes are passed as AAD to the AEAD; see §4.2)
9+N     4       Ciphertext length, big-endian uint32
13+N    M       Ciphertext (includes AEAD tag appended by cryptography library)
```

Total minimum size: 13 bytes + header + ciphertext.

**AAD binding:** The exact byte slice of the header JSON (offsets 9..9+N) is passed as
`associated_data` to AEAD encryption and decryption. Consequently the four magic/version
bytes (offsets 0..4) and the length fields (offsets 5..9, 9+N..13+N) are **not**
authenticated by the AEAD tag; they are validated structurally by `vault_format.unpack`
before any cryptographic step. Any byte change inside the header JSON window causes
decryption to fail with `DecryptionError`, indistinguishable from a wrong passphrase.

### 6.2 Header JSON (non-secret, minimised)

Only fields required to derive the key and decrypt the payload are stored in the
unencrypted header. Metadata such as creation timestamp, creating-app version, hostname,
and free-text description live exclusively in the encrypted `VaultManifest`. This
minimises the fingerprinting surface for an attacker who has read-only access to a
vault file.

```json
{
  "format": "GPGMEISTER_VAULT",
  "version": 2,
  "kdf": {
    "algorithm": "argon2id",
    "salt_b64": "<base64-encoded 16-byte random salt>",
    "time_cost": 3,
    "memory_cost": 262144,
    "parallelism": 4,
    "hash_len": 32
  },
  "cipher": {
    "algorithm": "chacha20-poly1305",
    "nonce_b64": "<base64-encoded 12-byte random nonce>"
  }
}
```

The header is serialised with **canonical JSON** (UTF-8, sorted keys, no insignificant
whitespace, no `\u` escapes for ASCII printables) so the same logical header produces
the same byte sequence on every platform. This is essential because the bytes are used
as AAD (§6.1) — any encoder variation would break decryption portability.

**Fields explicitly excluded** from the header (and instead stored inside the encrypted
manifest, §6.3): `created_at`, `app_version`, `created_by`, `description`, `hostname`,
and any user-supplied free-text metadata.

### 6.3 Encrypted Payload

Plaintext before encryption: msgpack-serialized `VaultManifest`.

After decryption and deserialization, the manifest contains:

```
VaultManifest
  created_by:   str        (OS user at export time; optional, may be empty)
  created_at:   str        (UTC ISO 8601)
  app_version:  str        (semver of GPG Meister that wrote the vault)
  description:  str        (user-supplied free text)
  keys: list[VaultKeyEntry]
    fingerprint:         str (40-char hex)
    user_ids:            list[str]
    public_key_armored:  str
    private_key_armored: str | None
    has_private_key:     bool
    created_at:          str
    expires_at:          str | None
```

The manifest is never written to disk in plaintext.

---

## 7. Dependency List

### 7.1 Runtime Dependencies

| Package          | Version    | Purpose                                      |
|------------------|------------|----------------------------------------------|
| PySide6          | >= 6.7     | Desktop GUI framework (LGPL)                 |
| python-gnupg     | >= 0.5.3   | GPG subprocess wrapper                       |
| cryptography     | >= 42.0    | ChaCha20-Poly1305, AES-256-GCM, SHA-256      |
| argon2-cffi      | >= 25.1    | Argon2id key derivation                      |
| pydantic         | >= 2.7     | Domain models, validation, serialization     |
| msgpack          | >= 1.0     | Binary vault payload serialization           |
| structlog        | >= 24.0    | Structured logging with redaction pipeline   |

### 7.2 Development Dependencies

| Package          | Purpose                                      |
|------------------|----------------------------------------------|
| uv               | Dependency management, virtual environment   |
| ruff             | Linting and formatting                       |
| mypy             | Static type checking (strict mode)           |
| pytest           | Test runner                                  |
| pytest-qt        | PySide6 widget testing utilities             |
| pytest-cov       | Coverage reporting                           |

### 7.3 System Dependency

| Dependency  | Minimum version | Notes                                      |
|-------------|-----------------|---------------------------------------------|
| GnuPG       | 2.2.0           | Must be installed separately by the user; <2.4.0 raises a non-blocking warning |

### 7.4 Supply-Chain Hygiene

- `uv.lock` is committed to VCS; CI verifies `uv sync --locked` produces an identical
  tree.
- `pip-audit` (or `uv pip audit`) runs in CI on every push against the locked
  dependencies. A known vulnerability with a fix available blocks merge; one without a
  fix raises a tracked issue.
- A CycloneDX SBOM is generated as a release artefact (`cyclonedx-py`) and attached to
  every signed release.
- Dependencies are pinned to specific minor-version-permissive ranges in
  `pyproject.toml`; major upgrades go through code review and a manual security review
  of the changelog.
- `cryptography`, `argon2-cffi`, `python-gnupg`, and `pydantic` are flagged as
  *crypto-critical* in a comment block in `pyproject.toml`; their upgrades require an
  explicit sign-off in the PR description.

---

## 8. Testing Strategy

### 8.1 Isolated GPG Environment

Every test that calls `gpg_service.py` uses a dedicated temporary GPG home directory
created by a pytest fixture in `conftest.py`. Test keys are generated once per test
session and cached. No test touches the developer's personal GPG keyring.

### 8.2 Unit Tests (no GPG required)

- `test_kdf.py` — derive key, verify output length, verify different salts produce
  different keys, verify wrong parameters are rejected.
- `test_aead.py` — encrypt/decrypt roundtrip, tampered ciphertext raises `DecryptionError`,
  wrong key raises `DecryptionError`.
- `test_vault_format.py` — pack/unpack roundtrip, truncated file raises `VaultFormatError`,
  wrong magic raises `VaultFormatError`, unsupported version raises `VaultFormatError`.
- `test_password_policy.py` — short passwords rejected, common passwords rejected,
  passphrase-style strings pass.
- `test_config_service.py` — load valid config, reject unknown keys, reject out-of-range
  values.

### 8.3 Integration Tests (GnuPG required)

- `test_gpg_service.py` — generate key, list keys, export public key, export private key,
  encrypt, decrypt, delete key.
- `test_vault_roundtrip.py` — full export then import cycle across two isolated GPG homes.
- `test_key_lifecycle.py` — create, list, export public key, import on second keyring,
  delete.

### 8.4 Security Tests

- `test_wrong_passphrase.py` — vault with wrong passphrase raises `DecryptionError`, error
  message does not reveal whether the passphrase or the ciphertext is the problem.
- `test_vault_tamper.py` — flip one byte in the vault ciphertext, verify decryption fails.
- `test_header_tamper.py` — flip one byte inside the header JSON window (e.g., change
  `time_cost` from `3` to `2`), verify decryption fails with `DecryptionError` because
  AAD validation rejects the modified header.
- `test_log_sanitization.py` — pass a log record containing a PGP block, verify it is
  redacted in the output. Also verify that fields named `passphrase`, `secret`,
  `plaintext` are redacted by key name regardless of value.
- `test_no_temp_plaintext.py` — after vault export, assert no `.tmp` or `.key` files
  remain in the temp directory; the only allowed leftover is the renamed final vault.
- `test_passphrase_not_in_argv.py` — monkeypatch `subprocess.Popen` and verify that no
  argv element contains the passphrase bytes for every operation that supplies one
  (key gen, sign, decrypt, secret export).
- `test_atomic_write.py` — simulate a write interruption by patching `os.replace` to
  raise after the tmp file is written; assert the target path is not overwritten and
  the tmp file is cleaned up.
- `test_path_whitelist.py` — point `AppConfig.gpg_binary_path` at a fake binary outside
  the whitelist; verify the application refuses to use it without an explicit trusted-
  hash entry in the config.
- `test_audit_log_isolation.py` — assert that the debug logger never writes audit
  events, and the audit logger refuses non-whitelisted event names.

---

## 9. Packaging Plan

### 9.1 Distribution Format

| Platform | Format                        | GPG requirement                          |
|----------|-------------------------------|------------------------------------------|
| Linux    | AppImage or Flatpak           | System GnuPG or bundled in image         |
| Windows  | PyInstaller one-folder bundle | Gpg4win must be installed separately     |
| macOS    | .app bundle via py2app        | GPG Suite or Homebrew GnuPG required     |

### 9.2 GPG Detection at Startup (path hardening)

GPG binary resolution follows a **whitelist-first** policy. The application will not
silently execute a binary discovered via `PATH` unless its canonical path appears in
the platform whitelist.

**Whitelist of trusted standard paths** (resolved via `Path.resolve(strict=True)`
before comparison, so symlinks cannot bypass the check):

| Platform | Whitelisted canonical paths                                              |
|----------|--------------------------------------------------------------------------|
| Linux    | `/usr/bin/gpg`, `/usr/bin/gpg2`, `/usr/local/bin/gpg`, `/usr/local/bin/gpg2`, `/bin/gpg`, `/snap/bin/gpg` |
| macOS    | `/usr/local/bin/gpg`, `/usr/local/bin/gpg2`, `/opt/homebrew/bin/gpg`, `/opt/homebrew/bin/gpg2`, `/usr/local/MacGPG2/bin/gpg2` |
| Windows  | `C:\Program Files\GnuPG\bin\gpg.exe`, `C:\Program Files (x86)\GnuPG\bin\gpg.exe`, `C:\Program Files\Git\usr\bin\gpg.exe` |

**Resolution order:**
1. **User override** (`AppConfig.gpg_binary_path`): if set, the application uses this
   path. If the path is **not** in the whitelist, a one-time confirmation dialog opens
   showing the resolved absolute path and a fingerprint of the binary
   (SHA-256 of the file). The user must explicitly accept. The acceptance is stored
   together with the binary's SHA-256 in `AppConfig.gpg_binary_trusted_hash`; subsequent
   startups re-verify the hash and re-prompt if it changes.
2. **Whitelist scan:** the first whitelisted path that exists is used.
3. **Last-resort `PATH` lookup:** only used to *display* a discovered location in the
   setup dialog. Such a discovered binary is **never executed** without the user
   selecting it as an override (Step 1 above), at which point the unfamiliar-path
   dialog applies.

**Additional hardening:**
- On POSIX, the resolved binary's `stat()` is inspected:
  - `st_uid == 0` (root-owned) when the path is in the whitelist. Deviation produces a
    warning but is not blocking (some package managers and Homebrew install user-owned).
  - The file must not be group- or world-writable (`st_mode & 0o022 == 0`). Violation
    is a hard fail.
- Symlinks pointing outside the whitelist roots are rejected even if the link itself
  lives at a whitelisted name (resolved path must also be whitelisted).
- The chosen path is logged as a `gpg_binary_resolved` audit event (§2.11) with
  absolute path and SHA-256, on every launch.

If no GPG binary is found anywhere, a non-dismissible setup dialog opens with platform-
specific install instructions and a link to verify the GnuPG download signature.

---

## 10. Implementation Order

The following sequence minimises blocked work and ensures each layer is testable before
the next layer depends on it.

```
Phase 1 — Foundation (no UI)
  1.  pyproject.toml, uv.lock, ruff/mypy configuration
  2.  storage/paths.py — XDG path resolution
  3.  models/ — all Pydantic models
  4.  security/secure_bytes.py — SecureBytes context manager
  5.  security/kdf.py + unit tests
  6.  security/aead.py + unit tests
  7.  security/vault_format.py + unit tests
  8.  security/password_policy.py + unit tests

Phase 2 — GPG Integration
  9.  startup/gpg_detector.py
  10. services/gpg_service.py + integration tests
  11. services/key_service.py + integration tests
  12. services/message_service.py + integration tests
  13. services/vault_service.py + integration tests (vault roundtrip)
  14. services/config_service.py + unit tests

Phase 3 — Storage
  15. storage/permissions.py
  16. storage/atomic_write.py + storage/file_lock.py + unit tests
  17. storage/metadata_store.py + unit tests
  18. storage/log_config.py (structlog + redaction filter)
  19. storage/audit_log.py (separate audit channel + hash chain) + unit tests

Phase 4 — UI Shell
  20. ui/main_window.py — tab container, startup check display
  21. ui/widgets/ — passphrase_field, fingerprint_label, warning_banner, clipboard_button
  22. ui/errors/ — UserError + error_catalog (§14.1)
  23. i18n/ scaffolding — Qt translator wiring, en + de skeletons, glossary files
  24. startup/environment_check.py (incl. swap-encryption probe)

Phase 5 — Key Views
  25. ui/keys/key_list_viewmodel.py + key_list_view.py
  26. ui/keys/key_create_viewmodel.py + key_create_view.py (Ed25519 default)
  27. ui/keys/key_detail_view.py
  28. ui/keys/public_key_import_view.py
  29. First-launch keyring import wizard (from system ~/.gnupg/)
  30. Post-key-gen backup banner (§14.3)

Phase 6 — Message Views
  31. ui/messages/encrypt_viewmodel.py + encrypt_view.py (recipient confirm panel §14.2)
  32. ui/messages/decrypt_viewmodel.py + decrypt_view.py
  33. ui/messages/sign_view.py + verify_view.py

Phase 7 — Vault Views
  34. ui/vault/vault_export_viewmodel.py + vault_export_view.py
  35. ui/vault/vault_import_viewmodel.py + vault_import_view.py (multi-step wizard §14.4)
  36. Backup-staleness reminder on launch (§14.3)

Phase 8 — Help, Settings, and Polish
  37. ui/help/ — Help tab, glossary, security-boundaries page (§14.5)
  38. ui/settings/settings_viewmodel.py + settings_view.py (incl. cipher/KDF/locale)
  39. Full German translation pass; CI translation-coverage gate
  40. Accessibility audit: keyboard-only walkthrough, screen reader spot-checks,
      high-contrast theme verification (§14.6)
  41. Security tests (tamper, header-AAD, wrong passphrase, log sanitization,
      argv-passphrase, atomic write, path whitelist, audit-log isolation)
  42. End-to-end test: full vault export + import cycle via UI

Phase 9 — Packaging
  43. AppImage/Flatpak (Linux)
  44. PyInstaller bundle (Windows)
  45. py2app bundle (macOS)
  46. CycloneDX SBOM generation + release signing
```

---

## 11. Threat Model (Updated)

### 11.1 Protected Against

| Threat                                   | Mitigation                                      |
|------------------------------------------|-------------------------------------------------|
| Accidental private key exposure in logs  | structlog key-name deny-list + PGP block content match (§5.4) |
| Shell injection via GPG arguments        | python-gnupg without shell=True + input validation + key-length enum (§4.5) |
| Passphrase visible in process listing    | `--passphrase-fd` via stdin only; argv-scan assertion + test (§5.6) |
| Vault payload tampering                  | AEAD authentication tag                         |
| Vault header tampering (KDF downgrade)   | Header bytes bound to AEAD tag via AAD (§4.2, §6.1) |
| Vault file half-written / partial state  | Atomic tmp+rename+fsync on write (§4.6)         |
| Concurrent vault writes from two instances | Advisory file lock (`flock`/`msvcrt.locking`) (§4.6) |
| Weak vault passphrases                   | Argon2id + password policy + parameter floor (§2.5) |
| Clipboard plaintext lingering            | Auto-clear timer + user warning                 |
| Wrong recipient encryption               | Fingerprint confirmation dialog before encrypt  |
| Vault transfer corruption                | SHA-256 checksum sidecar                        |
| Temp plaintext files on disk             | All sensitive operations in-memory only; SecureBytes (§4.4) |
| Vault passphrase reuse as GPG passphrase | UX separation + explicit warning                |
| Nonce reuse in AEAD                      | Fresh random 12-byte nonce per vault write      |
| Tampered or substituted GPG binary       | Whitelisted standard paths + SHA-256 trust pinning for user overrides (§9.2) |
| Plaintext leakage to swap                | mlock where supported + swap-encryption check at startup (§5.5) |
| Suppressed/edited diagnostic log hiding crypto events | Separate append-only audit log with optional hash chain (§2.11) |
| Stale dependency with known CVE          | `pip-audit` in CI + crypto-critical sign-off (§7.4) |
| Header metadata fingerprinting           | Header minimised to KDF/cipher params only (§6.2) |

### 11.2 Out of Scope

| Threat                                   | Reason                                          |
|------------------------------------------|-------------------------------------------------|
| Keyloggers / screen capture malware      | OS-level threat, outside application scope      |
| Compromised GnuPG package from distro    | Upstream supply-chain threat; path whitelist + SHA-256 pinning (§9.2) detects post-install tampering but cannot detect a backdoor present at install time |
| Memory scraping by root/kernel           | mlock mitigates but does not prevent root       |
| Physical access to unlocked device       | OS responsibility                               |
| Quantum attacks on RSA/AES keys          | Long-term concern; not in MVP scope             |
| Side-channel attacks on the local CPU    | Hardware-level threat; ChaCha20 reduces but does not eliminate the cache-timing surface |

These limitations are documented in the application's Help section.

---

## 12. Non-Goals (Explicit)

The following will not be implemented:

- Custom cryptographic algorithms or any modification to AEAD/KDF primitives.
- Online key server integration (no keyserver uploads or downloads).
- Automatic vault upload to cloud storage.
- Server-side decryption or key generation.
- Storing any passphrase (GPG or vault) on disk or in the config file.
- Auto-unlocking all GPG keys from the vault master passphrase.
- Silent private key export (always requires user confirmation).
- Web UI or remote access.

---

## 13. Resolved Design Decisions

The following items were open in v1 of this plan and are decided here.

1. **GPG home directory — dedicated keyring (default).**
   The application uses `$XDG_DATA_HOME/gpg-meister/gnupg/` as its GPG home and never
   touches the user's `~/.gnupg/` keyring. Rationale: avoids side effects on the user's
   personal keys, keeps test/dev keys isolated, and removes a class of accidental-delete
   bugs. A one-time **import wizard** runs on first launch, reading the user's system
   keyring (read-only) and offering to copy selected public/private keys into the
   application keyring. The wizard never deletes from `~/.gnupg/`. Users can re-run it
   from the Settings tab.

2. **Default key algorithm — Ed25519 + Curve25519.**
   New keys are generated as an Ed25519 signing primary with a Curve25519 (cv25519)
   encryption subkey. RSA remains available under a "Legacy / interoperability" option
   in the create-key dialog with sizes restricted to `{3072, 4096}` (2048 is no longer
   offered for new keys but is still readable for imports). The UI explains the choice
   in one sentence: "Ed25519 is faster, shorter, and the modern GnuPG default; choose
   RSA only if you must interoperate with software that does not support Ed25519."

3. **Message protection order — sign-then-encrypt (GPG default).**
   The `MessageService` invokes GnuPG with its default order (sign-then-encrypt) for
   maximum interoperability with the wider PGP ecosystem. The theoretical surreptitious-
   forwarding concern is mitigated at the UI level by always displaying the *signer*
   and *intended recipient(s)* of a decrypted message in the verify panel, and by
   warning when a decrypted signed message names a recipient that is not us.

4. **Minimum supported GnuPG version.**
   The hard floor is GnuPG **2.2.0** (released 2017) — older versions are refused at
   startup. A non-blocking warning is shown for versions below **2.4.0** (2022),
   noting that Kyber/PQC subkey support and several stability fixes require a newer
   GnuPG. The application records the version as a `gpg_binary_resolved` audit event.

5. **Cipher default — ChaCha20-Poly1305.**
   ChaCha20-Poly1305 is the default vault cipher. AES-256-GCM is exposed in Settings
   as an alternative for users on hardware with dedicated AES-NI and a policy reason
   to prefer NIST-standardised ciphers. The header records the choice so a vault
   created with one cipher can always be opened by the other build of the app.

6. **KDF profile selection.**
   The high-memory Argon2id profile (§2.5) is the default. A balanced profile is
   offered on low-memory hosts with an explicit user acknowledgement; downgrades below
   the policy floor are refused.

---

## 14. User Experience and Accessibility Requirements

Security is only effective if users can operate the application correctly. The following
requirements are part of the product definition, not nice-to-haves — a confusing error
or an inaccessible dialog directly leads to insecure workarounds (e.g., user picks the
wrong recipient because the fingerprint was hidden behind a tooltip).

### 14.1 Error Comprehensibility

Every error surfaced to the user must explain **what happened**, **why it happened**
(in plain language), and **what the user can do next**. Stack traces and library error
messages never reach the UI; they are written to the diagnostic log only.

All error messages are routed through `ui/errors/error_catalog.py`, a single source
mapping internal error classes to user-facing strings (translated, see §14.7).
ViewModels emit a typed `operation_failed = Signal(UserError)` rather than a free string;
the View renders the catalog entry. This guarantees consistency and translatability.

**Concrete error catalog (initial set):**

| Internal cause                             | User-facing message (English baseline)                                                                 | Action offered          |
|--------------------------------------------|---------------------------------------------------------------------------------------------------------|-------------------------|
| `DecryptionError` on vault open            | "The vault could not be opened. The passphrase may be wrong, or the file may be damaged or tampered with." | Retry / Cancel          |
| `GPGBinaryNotFound`                        | "GPG Meister needs GnuPG installed on this computer, but none was found. GnuPG is the underlying program that performs the cryptography." | Open install guide / Choose path |
| `GPGVersionTooOld`                         | "Your installed GnuPG (version X.Y.Z) is too old. GPG Meister requires version 2.2.0 or newer." | Open upgrade guide       |
| `KeyExpiredError` during encrypt           | "The key for &lt;name &lt;email&gt;&gt; expired on &lt;date&gt;. Encrypted messages may not be decryptable by the recipient." | Continue anyway / Cancel |
| `KeyRevokedError` during encrypt           | "The key for &lt;name &lt;email&gt;&gt; was revoked by its owner. Do not use this key — the owner has marked it as compromised or replaced." | Cancel (no override)     |
| `KeyNotTrustedError` during encrypt        | "You have not marked &lt;fingerprint&gt; as trusted. Verify it through a separate channel (e.g., phone call) before sending sensitive data." | Verify and trust / Continue once / Cancel |
| `SignatureInvalidError` during verify      | "The signature on this message is invalid. The message may have been altered after signing, or the signer's key was not the one expected." | Show details             |
| `SignerUnknownError` during verify         | "This message was signed by an unknown key (&lt;fingerprint&gt;). Import the signer's public key to verify the signature." | Import key…              |
| `VaultFormatError`                         | "This file does not look like a GPG Meister vault. It may be corrupted or of a different format." | Choose another file      |
| `VaultChecksumMismatch`                    | "The vault's checksum does not match. The file may have been damaged during transfer." | Open anyway / Cancel     |
| `LowEntropyPassphraseError`                | "This passphrase is too easy to guess. Use at least 4 unrelated words or 12 mixed characters." | (inline hint, not modal) |

Every error message:
- Avoids jargon unless the term is defined in the in-app glossary (§14.5).
- Names the affected object (filename, fingerprint, recipient) when applicable.
- Never reveals internal paths, exception types, or stack traces.
- Distinguishes "this is unusual" (warning) from "this cannot proceed" (error) visually
  (icon + colour + structure).

### 14.2 Recipient Safety (verschlüsseln an die richtigen Empfänger)

Before any encrypt operation, the application shows a **recipient confirmation panel**
with, per recipient:

- Primary user ID (Name &lt;email&gt;).
- Full 40-character fingerprint, displayed in spaced groups (`XXXX XXXX … XXXX XXXX`)
  in a monospace font, with a "copy" button.
- Key creation date and expiry (or "no expiry").
- Trust state, with a clear icon and label:
  - **Verified by you** (locally signed): green check.
  - **Marked trusted but unsigned**: yellow check.
  - **Unknown trust**: yellow warning.
  - **Not trusted / expired / revoked**: red warning, with the operation blocked or
    requiring an explicit override checkbox.
- Source of the key: `Local keyring`, `Imported from vault &lt;name&gt;`, or
  `Imported from file &lt;name&gt; on &lt;date&gt;`.

The encrypt button is **disabled by default** until the user actively confirms the
recipient set via a separate "I have verified the recipients" checkbox in the panel.
This prevents one-click accidental encryption to the wrong recipient.

When encrypting to multiple recipients, all are listed with their trust states. A
single untrusted recipient does not block the operation but is highlighted; the
confirmation checkbox label changes to "I want to send this message even though one or
more recipients are not verified."

### 14.3 Backup Reminders (Vault-Backup)

- Immediately after a new private key is generated, a non-modal banner appears on the
  Keys tab: "You just created a new key. Create a vault backup so you can restore it
  later." with a primary action button to open the vault export flow.
- The `metadata_store` records the timestamp of the last successful vault export
  (`vault_record.creation_timestamp`).
- On every launch, the application compares `last_export_timestamp` against the
  newest `key_metadata.import_timestamp`. If there are private keys newer than the most
  recent backup, or no backup exists at all, a soft warning appears in the status bar:
  "No backup since &lt;date&gt; — &lt;N&gt; key(s) are not in any vault."
- The warning is dismissible per session but reappears on the next launch until a
  fresh backup is taken.
- A configurable interval setting (`AppConfig.backup_reminder_days`, default 30) drives
  a periodic gentle reminder even when no new keys were added.

### 14.4 Vault Import Wizard

The import flow is a wizard, not a single dialog:

1. **Select vault file.** The wizard probes the file before asking for the passphrase
   — magic bytes are checked, the header is parsed, and any structural problem is
   reported with a clear message (§14.1 catalog).
2. **Enter master passphrase.** Field is masked by default with a "show" toggle.
   Caps-Lock state is indicated. Wrong passphrase yields the §14.1 message; a brief
   500 ms delay throttles trivial guessing without preventing legitimate retries.
3. **Preview manifest contents.** A list shows every key in the vault with: user IDs,
   fingerprint, has-private-key flag, creation date, expiry. The preview is read-only
   and does not modify the local keyring.
4. **Select keys to import.** Each row has a checkbox; the "select all" toggle is
   explicit. Public-only keys and full key pairs are visually distinguished.
5. **Conflict resolution.** For each selected key that already exists in the local
   keyring, the wizard shows a per-key choice:
   - **Skip** (default): keep the local version untouched.
   - **Merge user IDs and subkeys**: GnuPG-native merge (`gpg --import` of the armored
     block).
   - **Replace**: archive the existing local key (export to a timestamped file in the
     data directory before deletion), then import the vault version. A confirmation
     dialog names the archive path.
   The wizard never silently overwrites a private key.
6. **Summary and import.** A pre-flight summary lists exactly what will happen. After
   the user confirms, imports are performed sequentially; each result (success / skip /
   error per key) is shown in a final report screen with a "save report" button.

Wizard navigation supports Back/Next, Cancel at every step, and full keyboard control
(§14.6).

### 14.5 In-App Help and Glossary

- A dedicated **Help** tab in the main window, not a separate window, so help context
  is one click away.
- Sections:
  - **First steps**: generate a key, encrypt your first message, create a vault.
  - **Glossary**: plain-language definitions of `Key`, `Public/private key`,
    `Fingerprint`, `Signature`, `Trust`, `Revocation`, `Vault`, `Passphrase`,
    `KDF / Argon2id`, `AEAD / ChaCha20-Poly1305`. Each glossary entry is also reachable
    via a small `?` icon next to the corresponding UI element.
  - **Security boundaries**: explicit, plain-language reproduction of §11.2 — what the
    app does **not** protect against (keyloggers, root access, compromised OS, quantum
    attacks). This is intentionally surfaced, not hidden, so users can make informed
    decisions.
  - **Troubleshooting**: common errors from the §14.1 catalog with longer-form
    explanations.
- Every error dialog includes a "Learn more" link that opens the relevant Help section.

### 14.6 Accessibility (Barrierefreiheit)

Compliance target: **WCAG 2.2 Level AA** for desktop applications, as adapted for Qt.

- **Keyboard:** every action reachable by keyboard. Standard shortcuts respected
  (Tab/Shift-Tab traversal, Enter to confirm primary action, Esc to cancel modal).
  No mouse-only interactions. A discoverable "Show keyboard shortcuts" entry in the
  Help menu lists all bindings.
- **Screen readers:** every widget has a meaningful accessible name and description
  via `QWidget.setAccessibleName` / `setAccessibleDescription`. Tested on Orca (Linux),
  NVDA (Windows), and VoiceOver (macOS). Fingerprint labels announce in groups
  ("Foxtrot Charlie three…") instead of character-by-character, configurable.
- **Contrast:** all foreground/background pairs meet WCAG 2.2 AA contrast ratios
  (4.5:1 for normal text, 3:1 for large text). A high-contrast theme is shipped and
  selectable in Settings.
- **Scalable typography:** font size respects the OS-level scaling setting. An in-app
  scale slider (75 %–200 %) overrides if needed. Layouts use Qt's layout managers so
  resizing does not clip critical labels (fingerprints, error messages).
- **Colour is never the sole indicator:** trust states, validity, and errors always
  pair a colour with an icon and a text label.
- **Reduced motion:** any animation (banner slide, progress spinner) can be disabled
  via a Settings option, and honours the OS reduced-motion preference where available.
- **Focus visibility:** keyboard focus is rendered with a high-contrast outline,
  never `outline: none`.

An accessibility audit is a release gate (§10, Phase 8): a manual checklist run with
each major version against keyboard-only, screen reader, and high-contrast scenarios.

### 14.7 Internationalisation (i18n)

- **Locales at launch:** German (`de`) and English (`en`), with English as the
  fallback for any missing string. Locale is auto-detected from the OS and overridable
  in Settings.
- **Mechanism:** Qt's `tr()` / `QTranslator` with `.ts` source files under
  `src/gpg_meister/i18n/`. Builds compile to `.qm` and ship inside the package.
- **String discipline:** no string concatenation for sentences; placeholders are
  always named (`{recipient}`, `{date}`) so translators can reorder. Plurals use Qt's
  `tr("…", n)` form.
- **Consistent terminology:** a glossary file (`i18n/terms_de.md`, `terms_en.md`) defines
  the canonical translation of every cryptographic term (e.g., *Schlüssel*,
  *Fingerabdruck*, *Signatur*, *Tresor*, *Passphrase*). Translators must use these
  terms; a CI lint compares translated strings against the glossary and warns on
  drift.
- **Right-to-left readiness:** layouts use Qt's RTL-aware widgets; while no RTL
  locale is bundled in v2, no hard-coded left/right margins or alignment block future
  addition.
- **Date and number formatting:** all timestamps shown in the UI use the user's
  locale via `QLocale`; the underlying storage always remains UTC ISO 8601.
- **Coverage gate:** the release build fails if any translation file has &lt; 100 %
  coverage of the source strings.
