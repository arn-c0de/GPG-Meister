"""Cryptographic error hierarchy.

Callers see only these classes; library-internal exceptions
(`argon2.exceptions.*`, `cryptography.exceptions.InvalidTag`, …) are wrapped before
crossing the security/ boundary.
"""

from __future__ import annotations


class CryptoError(Exception):
    """Base class for all errors raised by the security/ package."""


class KDFError(CryptoError):
    """Raised when key derivation fails (parameter violation, library failure)."""


class DecryptionError(CryptoError):
    """Raised on any AEAD decryption failure.

    The message intentionally does not distinguish between wrong key, tampered
    ciphertext, tampered AAD, or malformed input — this prevents leaking information
    about which factor caused the failure.
    """


class VaultFormatError(CryptoError):
    """Raised when the binary vault frame is structurally invalid."""
