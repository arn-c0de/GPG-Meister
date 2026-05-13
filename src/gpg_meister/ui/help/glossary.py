"""Canonical term definitions for the in-app glossary (planv2.md §14.5)."""

from __future__ import annotations

TERMS: dict[str, str] = {
    "Key": (
        "A mathematical object used to encrypt, decrypt, or sign data. "
        "In GnuPG, each key is identified by a unique fingerprint."
    ),
    "Public key": (
        "The shareable half of a key pair. Anyone can use your public key to encrypt "
        "messages that only you can read, or to verify signatures you created."
    ),
    "Private key": (
        "The secret half of a key pair. Never share this. GPG Meister always keeps "
        "private keys encrypted on disk, protected by your passphrase."
    ),
    "Fingerprint": (
        "A 40-character hexadecimal digest that uniquely identifies a key. "
        "Always verify a full fingerprint out-of-band before trusting a key."
    ),
    "Signature": (
        "A cryptographic proof that a message was created by the holder of a specific "
        "private key and has not been altered since signing."
    ),
    "Trust": (
        "Your local assessment of whether a public key really belongs to the claimed "
        "owner. Trust is never verified automatically — you must confirm it yourself, "
        "e.g., by reading the fingerprint over the phone."
    ),
    "Revocation": (
        "A special certificate that marks a key as no longer valid. Once revoked, "
        "messages encrypted to that key can no longer be decrypted with it, and "
        "signatures from it should no longer be trusted."
    ),
    "Vault": (
        "An encrypted backup file (.gpgm) that stores one or more GPG keys. "
        "Protected by a separate master passphrase using Argon2id key derivation "
        "and ChaCha20-Poly1305 authenticated encryption."
    ),
    "Passphrase": (
        "A secret phrase used to protect your private key or vault. Unlike a "
        "password, a passphrase is typically longer and made up of words. "
        "GPG Meister enforces minimum strength requirements."
    ),
    "KDF / Argon2id": (
        "Key Derivation Function. Argon2id is the algorithm used to derive an "
        "encryption key from your passphrase. It is deliberately slow and "
        "memory-intensive to resist brute-force attacks."
    ),
    "AEAD / ChaCha20-Poly1305": (
        "Authenticated Encryption with Associated Data. ChaCha20-Poly1305 encrypts "
        "the vault payload and authenticates it together with the header, so any "
        "tampering — including header modifications — is detected before decryption."
    ),
    "Keyring": (
        "The GPG Meister keyring is a dedicated, isolated GnuPG home directory "
        "separate from your system ~/.gnupg. Operations here never affect your "
        "system keyring."
    ),
}
