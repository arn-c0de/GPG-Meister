"""Shared deny-list for sensitive keys and values (planv2.md §5.4).

Both the audit log and the diagnostic log must refuse to persist secret
material. Keeping the deny-list in one place means a key name added here is
honoured by every sink at once, and the matching is case-insensitive and
substring-aware so near-miss names (``master_passphrase``, ``Passphrase``,
``priv_key``) cannot slip past redaction.
"""

from __future__ import annotations

# Exact key names (compared case-insensitively) that must never be persisted.
FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "passphrase",
        "password",
        "secret",
        "private_key",
        "private_key_armored",
        "armored_private",
        "plaintext",
        "decrypted",
        "vault_key",
        "derived_key",
        "salt",
        "pin",
        "token",
    }
)

# Case-insensitive substrings that mark a key as sensitive even when embedded in
# a larger name, e.g. ``master_passphrase``, ``oldPassword``, ``priv_key``.
# Only unambiguous multi-character stems live here; short, easily-colliding
# words (``pin``, ``salt``, ``token``) stay exact-match via FORBIDDEN_KEYS so we
# do not redact innocent keys such as ``mapping`` or ``spinner``.
_FORBIDDEN_KEY_SUBSTRINGS: frozenset[str] = frozenset(
    {
        "passphrase",
        "password",
        "secret",
        "private_key",
        "privkey",
        "priv_key",
        "plaintext",
        "derived_key",
        "vault_key",
        "mnemonic",
        "seed_phrase",
    }
)

# PGP armor headers that must never be logged verbatim.
CONTENT_TRIGGERS: tuple[str, ...] = (
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN PGP SECRET KEY BLOCK-----",
    "-----BEGIN PGP MESSAGE-----",
)


def is_forbidden_key(key: str) -> bool:
    """True when ``key`` names a value that must never be persisted."""
    lowered = key.lower()
    if lowered in FORBIDDEN_KEYS:
        return True
    return any(sub in lowered for sub in _FORBIDDEN_KEY_SUBSTRINGS)


def contains_secret_marker(value: object) -> bool:
    """True when a string value carries a PGP armor header."""
    return isinstance(value, str) and any(trigger in value for trigger in CONTENT_TRIGGERS)
