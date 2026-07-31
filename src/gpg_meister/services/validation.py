"""Input validation enforced before any value is passed to GPG (planv2.md §4.5).

All checks are pure functions that raise `GPGValidationError` on failure. They
never touch the GPG subprocess — they exist so that callers cannot construct an
invalid `subprocess` call by accident or by feeding through unsanitised user text.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Final

from gpg_meister.models.key_info import FINGERPRINT_LENGTH, KeyAlgorithm
from gpg_meister.services.errors import GPGValidationError

_FINGERPRINT_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9A-F]{40}$")
# Pragmatic email regex covering the dot-atom form of RFC 5321. We deliberately do
# NOT try to be exhaustive — the value will be embedded in a GPG user ID by the
# caller, not used for routing.
_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._%+-]{0,62}[A-Za-z0-9])?"
    r"@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)
_USER_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_EXPIRY_OFFSET_RE: Final[re.Pattern[str]] = re.compile(r"^[1-9][0-9]*[ymwd]$")

# What GnuPG accepts for "no expiry date", and what the UI's *Never* option sends.
NO_EXPIRY: Final[str] = "0"

# Allowed key lengths per algorithm.
_ALLOWED_KEY_LENGTHS: Final[dict[KeyAlgorithm, frozenset[int]]] = {
    KeyAlgorithm.RSA: frozenset({2048, 3072, 4096}),
    KeyAlgorithm.ECDSA: frozenset({256, 384, 521}),
    KeyAlgorithm.EDDSA: frozenset({255}),
    KeyAlgorithm.ECDH: frozenset({255}),
}


def validate_fingerprint(fingerprint: str) -> str:
    upper = fingerprint.upper()
    if len(upper) != FINGERPRINT_LENGTH or not _FINGERPRINT_RE.match(upper):
        raise GPGValidationError(
            f"fingerprint must be {FINGERPRINT_LENGTH} uppercase hex characters"
        )
    return upper


def validate_email(email: str) -> str:
    if not _EMAIL_RE.match(email):
        raise GPGValidationError(f"invalid email address: {email!r}")
    return email


def validate_user_name(name: str) -> str:
    """A GPG user ID name with a deliberately small ASCII allow-list."""
    stripped = name.strip()
    if not stripped:
        raise GPGValidationError("user name must not be empty")
    if not _USER_NAME_RE.match(stripped) or "--" in stripped:
        raise GPGValidationError(
            "user name must contain only ASCII letters, digits, spaces, dots, underscores and hyphens"
        )
    return stripped


def validate_key_algorithm_and_length(algorithm: KeyAlgorithm, length: int) -> None:
    allowed = _ALLOWED_KEY_LENGTHS.get(algorithm)
    if allowed is None:
        raise GPGValidationError(f"unsupported algorithm: {algorithm}")
    if length not in allowed:
        raise GPGValidationError(
            f"length {length} not allowed for {algorithm}; allowed: {sorted(allowed)}"
        )


def validate_expiry(value: str) -> str:
    """`0` for "never", an ISO 8601 date `YYYY-MM-DD`, or an offset `Ny`/`Nm`/`Nw`/`Nd`.

    ``0`` is GnuPG's own spelling of "does not expire" and is what the key
    creation dialog sends for its *Never* option — which this function used to
    reject, so choosing *Never* produced a validation error instead of a key.
    """
    if value == NO_EXPIRY:
        return value
    if _EXPIRY_OFFSET_RE.match(value):
        return value
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise GPGValidationError(
            f"expiry must be ISO 8601 date or offset like '2y'/'30d'; got {value!r}"
        ) from exc
    return value


def reject_passphrase_in_argv(argv: list[str], passphrase: bytes | bytearray | memoryview) -> None:
    """Assert that no element of `argv` contains the passphrase bytes.

    Run as a defence-in-depth check before every subprocess call that involves a
    passphrase. A violation indicates a programming bug and must abort the call.
    """
    if not passphrase:
        return
    needle = passphrase
    for item in argv:
        item_bytes = item.encode("utf-8", errors="ignore") if isinstance(item, str) else item
        if isinstance(item_bytes, bytes) and needle in item_bytes:
            raise GPGValidationError(
                "passphrase bytes appeared in subprocess argv — refusing to call GPG"
            )
