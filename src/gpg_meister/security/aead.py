"""Authenticated encryption with associated data.

The two supported AEAD algorithms (planv2.md §2.4) are ChaCha20-Poly1305 (default)
and AES-256-GCM (configurable). Both produce a ciphertext that includes the 16-byte
authentication tag at the end, as is the convention in PyCA's `cryptography` library.

All decryption failures — wrong key, tampered ciphertext, tampered AAD — raise the
same `DecryptionError` with a generic message (planv2.md §4.2).
"""

from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from gpg_meister.models.vault import NONCE_LEN, CipherAlgorithm
from gpg_meister.security.errors import DecryptionError
from gpg_meister.security.secure_bytes import SecureBytes

KEY_LEN = 32


def generate_nonce() -> bytes:
    return secrets.token_bytes(NONCE_LEN)


def _aead_for(cipher: CipherAlgorithm, key: memoryview) -> ChaCha20Poly1305 | AESGCM:
    if cipher is CipherAlgorithm.CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)
    if cipher is CipherAlgorithm.AES_256_GCM:
        return AESGCM(key)
    raise ValueError(f"unsupported cipher: {cipher}")


def _check_inputs(key: SecureBytes, nonce: bytes) -> None:
    if key.is_closed:
        raise DecryptionError("key buffer is closed")
    if len(key) != KEY_LEN:
        raise DecryptionError("key length mismatch")
    if len(nonce) != NONCE_LEN:
        raise DecryptionError("nonce length mismatch")


def encrypt(
    plaintext: bytes | bytearray | memoryview,
    key: SecureBytes,
    nonce: bytes,
    associated_data: bytes,
    cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305,
) -> bytes:
    """Return ciphertext-with-tag.

    `associated_data` is authenticated but not encrypted. It must be re-supplied
    verbatim at decryption time.
    """
    _check_inputs(key, nonce)
    # Pass the memoryview directly: cryptography accepts bytes-like objects,
    # avoiding an immutable bytes copy of the key on the Python heap.
    aead = _aead_for(cipher, key.view())
    return aead.encrypt(nonce, plaintext, associated_data)


def decrypt(
    ciphertext: bytes,
    key: SecureBytes,
    nonce: bytes,
    associated_data: bytes,
    cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305,
) -> bytes:
    """Decrypt and authenticate. Raises `DecryptionError` on any failure."""
    _check_inputs(key, nonce)
    aead = _aead_for(cipher, key.view())
    try:
        return aead.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag as exc:  # noqa: F841 — message intentionally generic
        raise DecryptionError(
            "decryption failed: the passphrase, ciphertext, or header may be wrong"
        ) from None
