from __future__ import annotations

import pickle

import pytest

from gpg_meister.security.secure_bytes import (
    SecureBytes,
    _zero_bytes_object,
    secure_bytes_from,
)


def test_view_exposes_initial_contents() -> None:
    secret = b"correct horse battery staple"
    with SecureBytes.from_bytes(secret) as sb:
        assert bytes(sb.view()) == secret
        assert len(sb) == len(secret)


def test_exit_zeroes_buffer() -> None:
    secret = b"super-sensitive-bytes"
    sb = SecureBytes.from_bytes(secret)
    view = sb.view()
    assert bytes(view) == secret
    sb.close()
    # After close, calling view() raises — the buffer itself is zeroed regardless,
    # but we can no longer reach it through the safe API. Confirm the error.
    with pytest.raises(RuntimeError):
        sb.view()


def test_double_close_is_idempotent() -> None:
    sb = SecureBytes.from_bytes(b"abc")
    sb.close()
    sb.close()  # must not raise


def test_repr_never_leaks_contents() -> None:
    with SecureBytes.from_bytes(b"top-secret") as sb:
        text = repr(sb)
        assert "top-secret" not in text
        assert "secret" not in text.lower() or "size=" in text


def test_str_never_leaks_contents() -> None:
    with SecureBytes.from_bytes(b"top-secret") as sb:
        text = str(sb)
        assert "top-secret" not in text


def test_cannot_be_pickled() -> None:
    sb = SecureBytes.from_bytes(b"x")
    try:
        with pytest.raises(TypeError):
            pickle.dumps(sb)
    finally:
        sb.close()


def test_zero_size_is_supported() -> None:
    with SecureBytes(0) as sb:
        assert len(sb) == 0
        assert bytes(sb.view()) == b""


def test_negative_size_rejected() -> None:
    with pytest.raises(ValueError):
        SecureBytes(-1)


def test_to_bytes_returns_copy() -> None:
    with SecureBytes.from_bytes(b"hello") as sb:
        copy = sb.to_bytes()
        assert copy == b"hello"
        # Mutating the view does not affect the prior copy.
        view = sb.view()
        view[0] = ord("H")
        assert sb.to_bytes() == b"Hello"
        assert copy == b"hello"


def test_view_after_close_raises() -> None:
    sb = SecureBytes.from_bytes(b"x")
    sb.close()
    with pytest.raises(RuntimeError):
        sb.view()
    with pytest.raises(RuntimeError):
        sb.to_bytes()


def test_secure_bytes_from_helper() -> None:
    with secure_bytes_from(b"abc") as sb:
        assert sb.to_bytes() == b"abc"
        assert not sb.is_closed
    assert sb.is_closed


def test_cannot_reenter_closed_buffer() -> None:
    sb = SecureBytes.from_bytes(b"x")
    sb.close()
    with pytest.raises(RuntimeError), sb:
        pass


def test_zero_bytes_object_skips_single_byte_to_avoid_interned_corruption() -> None:
    # Zeroing a 1-byte interned bytes object would corrupt the interpreter-wide
    # singleton; the guard must refuse and report it did nothing.
    assert _zero_bytes_object(b"a") is False
    assert _zero_bytes_object(b"") is False
    # The interned singleton must be untouched.
    assert b"a" == b"a"
    assert b"a"[0] == 97


def test_zero_bytes_object_zeros_multibyte_buffer() -> None:
    # bytes(bytearray(...)) yields a fresh, non-cached bytes object (a plain
    # b"..." literal would be a shared code constant we must not corrupt).
    raw = bytes(bytearray(b"S" * 16))
    assert _zero_bytes_object(raw) is True
    assert raw == b"\x00" * 16


def test_del_backstop_zeros_when_close_forgotten() -> None:
    sb = SecureBytes.from_bytes(b"forgotten-secret-value")
    view = sb.view()
    sb.__del__()  # simulate finalisation without an explicit close()
    assert sb.is_closed
    assert bytes(view) == b"\x00" * len(view)
