# Plan vs Current Code

This document compares `planv2.md` with the real implementation in the repository today.

It is meant as a quick reality check.

## What matches the plan well

These parts are strongly aligned with the plan:

- PySide6 is the UI framework.
- The code is split into models, services, storage, startup, security, and UI.
- `python-gnupg` is the GPG integration layer.
- Vault encryption uses AEAD with ChaCha20-Poly1305 and AES-256-GCM support.
- Argon2id is the KDF.
- The vault has a binary frame with a JSON header and encrypted payload.
- The app uses XDG-style paths on POSIX systems.
- There is a separate audit log.
- File writes for important artifacts are atomic.

## Where the implementation is more concrete than the plan

The code adds a number of practical security details that are easy to miss in a pure design document:

- `GPGService` verifies required GPG options like loopback pinentry.
- the code checks that passphrases do not leak into subprocess argv
- vault parsing has explicit maximum sizes
- audit events use a whitelist
- forbidden audit payload keys are blocked at runtime
- `SecureBytes` prevents pickling and zeroizes memory on close
- GPG binary detection uses hash pinning for non-whitelisted binaries

## Where the implementation differs a bit from the wording in the plan

### Models

The plan says "Pydantic v2 dataclasses".

The actual code mostly uses immutable Pydantic `BaseModel` classes. The result is similar in practice, but the implementation detail is different.

### MVVM

The plan describes MVVM in a strict architectural sense.

The real code is a lighter Qt version of MVVM:

- Qt widgets as views
- signal-based viewmodels
- service calls through background workers

This is simpler than a full reactive binding system, but it fits the project well.

### Import dry-run language

The plan discusses safe import analysis.

The current `KeyService.plan_import()` uses `python-gnupg` scan support and current keyring state to classify import conflicts without changing the keyring. That is simpler and cleaner than a more complex manual subprocess parser.

## Where the code has evolved after the original plan

The codebase now includes a local key usage context layer:

- SQLite stores `label`, `purpose`, `platform`, and `notes`
- `KeyInfo` carries these fields
- `KeyService` merges GPG data with metadata
- the key detail dialog can edit the context
- the key list can show labels for easier identification

This is a real feature addition beyond the earlier plan wording.

## What to keep in mind when reading old plan notes

`planv2.md` is still useful for direction and rationale.

But for implementation truth, prefer the source code and these docs. Some details changed because:

- security fixes made the boundary stricter
- the real Qt workflow became clearer during implementation
- practical storage and UX needs added metadata and migration logic
