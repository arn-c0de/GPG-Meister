"""Service-layer error hierarchy.

These are translated to user-facing strings via `ui/errors/error_catalog.py`. The
service layer raises them with internal-only details; the UI catalog supplies the
end-user message.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Base class for all service-layer errors."""


class GPGServiceError(ServiceError):
    """Generic failure when invoking GnuPG."""


class GPGPassphraseError(GPGServiceError):
    """The GPG passphrase was wrong or missing."""


class GPGKeyNotFoundError(GPGServiceError):
    """The requested key is not present in the local keyring."""


class GPGValidationError(GPGServiceError):
    """An input failed validation before being passed to GPG."""


class GPGProcessError(GPGServiceError):
    """The GPG subprocess returned a non-zero status or unparseable output."""


class GPGCardError(GPGServiceError):
    """A smartcard (YubiKey / OpenPGP card) operation could not be completed.

    Raised when the token is not plugged in, the reader is unavailable, or the
    card refused the PIN. Distinct from ``GPGPassphraseError`` because the fix
    is different: insert the token rather than retype a passphrase.
    """


class GPGCardPinError(GPGCardError):
    """The card PIN was wrong or the card is blocked after too many attempts."""
