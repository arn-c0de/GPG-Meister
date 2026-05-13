# Security Modules

The security code lives in `src/gpg_meister/security`.

These modules do not know about Qt. They focus on sensitive bytes, key derivation, encryption, and vault framing rules.

## `secure_bytes.py`

`SecureBytes` is a short-lived container for sensitive data.

It gives the app:

- a writable in-memory buffer
- best-effort `mlock` on supported systems
- zeroization on close
- context-manager usage
- no pickling

Important limitation:

Python cannot guarantee perfect secret handling because copies may still exist inside CPython or third-party libraries. The code is honest about that and tries to reduce the exposure window.

## `kdf.py`

This module derives vault keys with Argon2id.

Main features:

- validates KDF parameters before use
- generates random salts
- derives a fixed-length key into `SecureBytes`
- supports simple benchmarking for profile tuning

The current default is still the high-memory profile from the model layer.

## `aead.py`

This module performs authenticated encryption with associated data.

Supported ciphers:

- `chacha20-poly1305`
- `aes-256-gcm`

The API is intentionally small:

- `generate_nonce()`
- `encrypt(...)`
- `decrypt(...)`

All decryption failures return the same generic error message. This is good because it avoids leaking details about whether the passphrase, ciphertext, or header was wrong.

## `vault_format.py`

This file defines the binary vault frame.

Main protections:

- fixed magic bytes
- explicit version byte
- canonical JSON header
- strict size limits for header and ciphertext
- validation on unpack
- no trailing bytes allowed

The header bytes are reused as AEAD associated data, so header tampering is detected during decryption.

## What is important in the real implementation

The code is more defensive than a simple architecture sketch:

- KDF bounds are enforced twice: in models and in runtime helpers.
- vault reads reject oversized payloads early.
- decryption does not expose detailed failure reasons.
- sensitive data stays in small helper types where possible.
