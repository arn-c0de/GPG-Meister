from __future__ import annotations

import pytest

from gpg_meister.models.kdf_params import KDFParams, balanced_params
from gpg_meister.security.errors import KDFError
from gpg_meister.security.kdf import (
    benchmark_params,
    default_params,
    derive_key,
    generate_salt,
)
from gpg_meister.security.secure_bytes import SecureBytes


@pytest.fixture
def fast_params() -> KDFParams:
    """A test profile that meets the floor but runs quickly."""
    return KDFParams(
        time_cost=2,
        memory_cost=19_456,
        parallelism=1,
        hash_len=32,
        salt_len=16,
    )


def test_generate_salt_returns_requested_length() -> None:
    salt = generate_salt(16)
    assert len(salt) == 16
    # A second call must produce a different salt with overwhelming probability.
    assert generate_salt(16) != salt


def test_generate_salt_rejects_too_short() -> None:
    with pytest.raises(KDFError):
        generate_salt(8)


def test_derive_key_returns_requested_length(fast_params: KDFParams) -> None:
    salt = generate_salt(fast_params.salt_len)
    with SecureBytes.from_bytes(b"hunter2") as pw:
        derived = derive_key(pw, salt, fast_params)
        try:
            assert len(derived) == fast_params.hash_len
        finally:
            derived.close()


def test_same_inputs_produce_same_key(fast_params: KDFParams) -> None:
    salt = generate_salt(fast_params.salt_len)
    with SecureBytes.from_bytes(b"hunter2") as pw1, SecureBytes.from_bytes(b"hunter2") as pw2:
        a = derive_key(pw1, salt, fast_params)
        b = derive_key(pw2, salt, fast_params)
        try:
            assert a.to_bytes() == b.to_bytes()
        finally:
            a.close()
            b.close()


def test_different_salts_produce_different_keys(fast_params: KDFParams) -> None:
    salt1 = generate_salt(fast_params.salt_len)
    salt2 = generate_salt(fast_params.salt_len)
    with SecureBytes.from_bytes(b"hunter2") as pw1, SecureBytes.from_bytes(b"hunter2") as pw2:
        a = derive_key(pw1, salt1, fast_params)
        b = derive_key(pw2, salt2, fast_params)
        try:
            assert a.to_bytes() != b.to_bytes()
        finally:
            a.close()
            b.close()


def test_different_passphrases_produce_different_keys(fast_params: KDFParams) -> None:
    salt = generate_salt(fast_params.salt_len)
    with SecureBytes.from_bytes(b"hunter2") as pw1, SecureBytes.from_bytes(b"hunter3") as pw2:
        a = derive_key(pw1, salt, fast_params)
        b = derive_key(pw2, salt, fast_params)
        try:
            assert a.to_bytes() != b.to_bytes()
        finally:
            a.close()
            b.close()


def test_wrong_salt_length_rejected(fast_params: KDFParams) -> None:
    with SecureBytes.from_bytes(b"x") as pw, pytest.raises(KDFError):
        derive_key(pw, b"\x00" * 8, fast_params)


def test_closed_passphrase_rejected(fast_params: KDFParams) -> None:
    pw = SecureBytes.from_bytes(b"x")
    pw.close()
    with pytest.raises(KDFError):
        derive_key(pw, generate_salt(fast_params.salt_len), fast_params)


def test_default_params_matches_high_memory_profile() -> None:
    p = default_params()
    assert p.memory_cost == 262_144


@pytest.mark.slow
def test_benchmark_returns_positive_time() -> None:
    # Use the balanced profile so the test runs in a few hundred ms, not seconds.
    elapsed = benchmark_params(balanced_params())
    assert elapsed > 0.0
