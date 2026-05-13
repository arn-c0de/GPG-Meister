# GPG Meister — English Terminology Glossary

This file defines the canonical English terms used throughout GPG Meister's UI
and documentation. Translators must use these exact terms in their translations.

## Cryptographic Terms

| Term | Definition |
|---|---|
| **Key** | A cryptographic key used to encrypt, decrypt, sign, or verify data. |
| **Public key** | The shareable part of a key pair. Anyone can use it to encrypt messages to you or verify your signatures. |
| **Private key** | The secret part of a key pair. Keep it safe — anyone with access to it can decrypt your messages and impersonate you. |
| **Key pair** | A matched public key and private key that work together. |
| **Fingerprint** | A short checksum of a public key, used to identify and verify it. Always verify fingerprints through a separate channel before trusting a key. |
| **Signature** | A cryptographic proof that a message was created by the holder of a specific private key and has not been altered since. |
| **Trust** | Your local assessment of whether a key genuinely belongs to the person named in it. GPG Meister never automatically trusts keys — you must verify them yourself. |
| **Revocation** | The act of permanently invalidating a key, signalling that it should no longer be used (e.g., because the private key was compromised). |
| **Passphrase** | A password that protects a private key or vault. Use a long passphrase — a sequence of four or more unrelated words is ideal. |
| **KDF / Argon2id** | Key Derivation Function. Transforms a passphrase into a cryptographic key. Argon2id is the recommended algorithm (RFC 9106) — it is intentionally slow and memory-intensive to resist brute-force attacks. |
| **AEAD / ChaCha20-Poly1305** | Authenticated Encryption with Associated Data. An encryption algorithm that simultaneously ensures confidentiality, integrity, and authenticity. ChaCha20-Poly1305 is the default vault cipher. |

## Application-Specific Terms

| Term | Definition |
|---|---|
| **Vault** | An encrypted backup file containing one or more GPG key pairs. Used to transfer keys between devices or store an offline backup. |
| **Vault master passphrase** | The passphrase that protects a vault file. Different from (and should not be the same as) the GPG key passphrase. |
| **Keyring** | The local collection of GPG keys managed by this application. Stored in the application's dedicated GnuPG home directory. |
