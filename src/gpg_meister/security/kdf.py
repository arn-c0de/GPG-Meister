"""Argon2id key derivation for vault keys.

Wraps `argon2.low_level.hash_secret_raw` so callers never see argon2-cffi types.
"""

from __future__ import annotations

import ctypes
import secrets
import time
from typing import TYPE_CHECKING

from argon2 import exceptions as argon2_exceptions
from argon2.low_level import Type, hash_secret_raw

from gpg_meister.models.kdf_params import (
    MAX_HASH_LEN,
    MAX_MEMORY_COST_KB,
    MAX_PARALLELISM,
    MAX_SALT_LEN,
    MAX_TIME_COST,
    MIN_HASH_LEN,
    MIN_MEMORY_COST_KB,
    MIN_SALT_LEN,
    MIN_TIME_COST,
    KDFAlgorithm,
    KDFParams,
    high_memory_params,
)
from gpg_meister.security.errors import KDFError
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object

if TYPE_CHECKING:
    pass


def generate_salt(length: int = MIN_SALT_LEN) -> bytes:
    if length < MIN_SALT_LEN:
        raise KDFError(f"salt length {length} is below the floor {MIN_SALT_LEN}")
    return secrets.token_bytes(length)


def _validate_params(params: KDFParams) -> None:
    if params.algorithm is not KDFAlgorithm.ARGON2ID:
        raise KDFError(f"unsupported KDF algorithm: {params.algorithm}")
    if not MIN_TIME_COST <= params.time_cost <= MAX_TIME_COST:
        raise KDFError(
            f"time_cost {params.time_cost} outside [{MIN_TIME_COST}, {MAX_TIME_COST}]"
        )
    if not MIN_MEMORY_COST_KB <= params.memory_cost <= MAX_MEMORY_COST_KB:
        raise KDFError(
            f"memory_cost {params.memory_cost} outside "
            f"[{MIN_MEMORY_COST_KB}, {MAX_MEMORY_COST_KB}] KiB"
        )
    if not 1 <= params.parallelism <= MAX_PARALLELISM:
        raise KDFError(
            f"parallelism {params.parallelism} outside [1, {MAX_PARALLELISM}]"
        )
    if not MIN_HASH_LEN <= params.hash_len <= MAX_HASH_LEN:
        raise KDFError(
            f"hash_len {params.hash_len} outside [{MIN_HASH_LEN}, {MAX_HASH_LEN}]"
        )
    if not MIN_SALT_LEN <= params.salt_len <= MAX_SALT_LEN:
        raise KDFError(
            f"salt_len {params.salt_len} outside [{MIN_SALT_LEN}, {MAX_SALT_LEN}]"
        )


def derive_key(passphrase: SecureBytes, salt: bytes, params: KDFParams) -> SecureBytes:
    """Derive a fixed-length key from a passphrase.

    The returned SecureBytes owns its buffer and must be closed by the caller
    (usually via `with`).
    """
    _validate_params(params)
    if len(salt) != params.salt_len:
        raise KDFError(
            f"salt length {len(salt)} does not match params.salt_len {params.salt_len}"
        )
    if passphrase.is_closed:
        raise KDFError("passphrase SecureBytes is closed")

    # Use bytearray for both the passphrase copy and the derived key — bytearray is
    # mutable so we can zero it in-place, unlike immutable bytes objects.
    passphrase_buf = bytearray(passphrase.view())
    try:
        # argon2-cffi >= 25.1.0 (with cffi >= 1.17 on Python 3.14+) may reject
        # bytearray in hash_secret_raw. Convert to a short-lived bytes copy.
        raw = hash_secret_raw(
            secret=bytes(passphrase_buf),
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            type=Type.ID,
        )
    except argon2_exceptions.Argon2Error as exc:
        raise KDFError(f"argon2id failed: {exc}") from exc
    finally:
        # Zero via ctypes.memset so no runtime can optimise the wipe away.
        _pbuf = (ctypes.c_char * len(passphrase_buf)).from_buffer(passphrase_buf)
        ctypes.memset(_pbuf, 0, len(passphrase_buf))

    # raw is a bytes object from argon2-cffi; copy to SecureBytes, then
    # best-effort zero the intermediate via the shared CPython hack.
    result = SecureBytes.from_bytes(raw)
    _zero_bytes_object(raw)
    return result


def benchmark_params(params: KDFParams) -> float:
    """Measure end-to-end derivation time in milliseconds.

    Used at first launch (planv2.md §2.5) to warn the user if the configured
    parameters are too weak for the hardware.
    """
    _validate_params(params)
    salt = generate_salt(params.salt_len)
    with SecureBytes.from_bytes(b"benchmark") as pw:
        start = time.perf_counter()
        derived = derive_key(pw, salt, params)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        derived.close()
    return elapsed_ms


def default_params() -> KDFParams:
    return high_memory_params()
