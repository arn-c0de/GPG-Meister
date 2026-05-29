"""Tests for the shared secret-scanning walkers in storage.secret_keys.

These back the de-duplication of the diagnostic-log redactor and the audit-log
rejector onto one traversal: both must catch a secret at any nesting depth,
including lists-of-lists.
"""

from __future__ import annotations

from gpg_meister.storage.secret_keys import (
    find_secret_violation,
    is_forbidden_key,
    redact_secrets,
)

_PGP = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc\n-----END PGP PRIVATE KEY BLOCK-----"
_R = "<R>"


# --------------------------------------------------------------- redact_secrets

def test_redact_forbidden_key_value() -> None:
    out = redact_secrets({"passphrase": "hunter2", "label": "ok"}, placeholder=_R)
    assert out == {"passphrase": _R, "label": "ok"}


def test_redact_pgp_block_value_regardless_of_key() -> None:
    out = redact_secrets({"arbitrary": _PGP}, placeholder=_R)
    assert out == {"arbitrary": _R}


def test_redact_nested_dict() -> None:
    out = redact_secrets({"ctx": {"inner": {"passphrase": "x"}}}, placeholder=_R)
    assert out == {"ctx": {"inner": {"passphrase": _R}}}


def test_redact_secret_in_list_of_dicts() -> None:
    out = redact_secrets({"items": [{"body": _PGP}]}, placeholder=_R)
    assert out == {"items": [{"body": _R}]}


def test_redact_secret_in_nested_list() -> None:
    # The tightening: a secret one list deeper must still be redacted.
    out = redact_secrets({"rows": [[_PGP]]}, placeholder=_R)
    assert out == {"rows": [[_R]]}


def test_redact_preserves_tuple_type() -> None:
    out = redact_secrets({"t": ("a", _PGP)}, placeholder=_R)
    assert out == {"t": ("a", _R)}
    assert isinstance(out["t"], tuple)  # type: ignore[index]


def test_redact_leaves_clean_data_untouched() -> None:
    data = {"a": 1, "b": ["x", {"c": "y"}], "has_private_key": True}
    assert redact_secrets(data, placeholder=_R) == data


# ----------------------------------------------------------- find_secret_violation

def test_find_clean_payload_returns_none() -> None:
    assert find_secret_violation({"fingerprint": "AB", "count": 3, "ok": [1, 2]}) is None


def test_find_forbidden_key() -> None:
    msg = find_secret_violation({"password": "x"})
    assert msg is not None and "forbidden" in msg


def test_find_reserved_key_top_level_only() -> None:
    reserved = frozenset({"event"})
    assert find_secret_violation({"event": "x"}, reserved=reserved) is not None
    # Nested 'event' is not an envelope collision and must be allowed.
    assert find_secret_violation({"ctx": {"event": "x"}}, reserved=reserved) is None


def test_find_secret_value() -> None:
    assert find_secret_violation({"note": _PGP}) is not None


def test_find_forbidden_key_in_list_of_dicts() -> None:
    msg = find_secret_violation({"keys": [{"private_key": "x"}]})
    assert msg is not None and "forbidden" in msg


def test_find_secret_in_nested_list() -> None:
    # The tightening: audit now also rejects a secret hidden in a list-of-lists.
    assert find_secret_violation({"rows": [[_PGP]]}) is not None


def test_forbidden_key_is_case_insensitive() -> None:
    assert is_forbidden_key("PassPhrase")
    assert find_secret_violation({"PassPhrase": "x"}) is not None
