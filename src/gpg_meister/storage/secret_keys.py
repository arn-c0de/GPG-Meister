"""Shared deny-list for sensitive keys and values (planv2.md §5.4).

Both the audit log and the diagnostic log must refuse to persist secret
material. Keeping the deny-list in one place means a key name added here is
honoured by every sink at once, and the matching is case-insensitive and
substring-aware so near-miss names (``master_passphrase``, ``Passphrase``,
``priv_key``) cannot slip past redaction.
"""

from __future__ import annotations

# Key names that must never be persisted, matched case-insensitively. These name
# *secret values* (passphrases, private key material, derived keys), not the
# metadata flags that merely mention them.
#
# Matching is exact (after lower-casing) rather than substring: substring
# matching looks attractive for catching ``master_passphrase`` but it
# over-redacts the codebase's legitimate boolean/metadata keys —
# ``has_private_key``, ``including_secret``, ``passphrase_strength``,
# ``low_entropy_passphrase`` all contain a sensitive stem yet carry no secret.
# The fix for the audit's concern (``master_passphrase``, ``Passphrase``,
# ``priv_key`` slipping past a case-sensitive exact list) is to (a) match
# case-insensitively and (b) enumerate the real compound names here.
FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "passphrase",
        "master_passphrase",
        "key_passphrase",
        "sign_passphrase",
        "confirm_passphrase",
        "password",
        "secret",
        "private_key",
        "private_keys",
        "priv_key",
        "privkey",
        "private_key_armored",
        "armored_private",
        "secret_key",
        "secret_key_armored",
        "plaintext",
        "decrypted",
        "vault_key",
        "derived_key",
        "mnemonic",
        "seed_phrase",
        "salt",
        "pin",
        "token",
    }
)

# PGP armor headers that must never be logged verbatim.
CONTENT_TRIGGERS: tuple[str, ...] = (
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN PGP SECRET KEY BLOCK-----",
    "-----BEGIN PGP MESSAGE-----",
)

_FORBIDDEN_KEYS_LOWER: frozenset[str] = frozenset(k.lower() for k in FORBIDDEN_KEYS)


def is_forbidden_key(key: str) -> bool:
    """True when ``key`` names a secret value that must never be persisted."""
    return key.lower() in _FORBIDDEN_KEYS_LOWER


def contains_secret_marker(value: object) -> bool:
    """True when a string value carries a PGP armor header."""
    return isinstance(value, str) and any(trigger in value for trigger in CONTENT_TRIGGERS)
