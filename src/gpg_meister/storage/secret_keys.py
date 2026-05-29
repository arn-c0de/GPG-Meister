"""Shared deny-list for sensitive keys and values (planv2.md §5.4).

Both the audit log and the diagnostic log must refuse to persist secret
material. Keeping the deny-list in one place means a key name added here is
honoured by every sink at once. Matching is case-insensitive and uses an
*exact* match against a curated set that enumerates the real compound names
(``master_passphrase``, ``priv_key``, …). Exact — not substring — matching is
deliberate: see the comment on ``FORBIDDEN_KEYS`` below for why substring
matching over-redacts legitimate metadata flags.
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


# The two consumers of the deny-list — the diagnostic logger (redacts) and the
# audit logger (rejects) — used to hand-roll their own dict/list/tuple recursion.
# They now share these two walkers so the traversal (and the depth at which a
# nested secret is caught) is defined and tested in exactly one place. Both
# recurse through dicts, lists *and* tuples at every depth, including
# lists-of-lists, so a secret cannot hide one container deeper than expected.


def redact_secrets(value: object, *, placeholder: str) -> object:
    """Return a deep copy of ``value`` with secrets replaced by ``placeholder``.

    A deny-listed key (its whole value) and any string value carrying a PGP
    armor header are replaced; everything else is copied through. Used by the
    diagnostic-log processor.
    """
    if isinstance(value, dict):
        out: dict[object, object] = {}
        for key, val in value.items():
            if (isinstance(key, str) and is_forbidden_key(key)) or contains_secret_marker(val):
                out[key] = placeholder
            else:
                out[key] = redact_secrets(val, placeholder=placeholder)
        return out
    if isinstance(value, (list, tuple)):
        items = [
            placeholder if contains_secret_marker(item) else redact_secrets(item, placeholder=placeholder)
            for item in value
        ]
        return tuple(items) if isinstance(value, tuple) else items
    return value


def find_secret_violation(value: object, *, reserved: frozenset[str] = frozenset()) -> str | None:
    """Return a description of the first policy violation in ``value``, or None.

    Mirrors :func:`redact_secrets`' traversal but *detects* instead of
    rewriting: a deny-listed key, a reserved envelope key (top level only), or a
    secret-marked value anywhere in the structure. Used by the audit logger,
    which raises on a non-None result.
    """
    if isinstance(value, dict):
        for key, val in value.items():
            if isinstance(key, str) and is_forbidden_key(key):
                return f"forbidden key {key!r} in audit payload"
            if reserved and key in reserved:
                return f"key {key!r} is reserved for the audit envelope"
            if contains_secret_marker(val):
                return f"value of key {key!r} looks like secret key material"
            nested = find_secret_violation(val)
            if nested is not None:
                return nested
    elif isinstance(value, (list, tuple)):
        for item in value:
            if contains_secret_marker(item):
                return "list value looks like secret key material"
            nested = find_secret_violation(item)
            if nested is not None:
                return nested
    return None
