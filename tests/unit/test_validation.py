from __future__ import annotations

import pytest

from gpg_meister.models.key_info import KeyAlgorithm
from gpg_meister.services.errors import GPGValidationError
from gpg_meister.services.validation import (
    reject_passphrase_in_argv,
    validate_email,
    validate_expiry,
    validate_fingerprint,
    validate_key_algorithm_and_length,
    validate_user_name,
)


def test_fingerprint_uppercased() -> None:
    fp = validate_fingerprint("abcdef0123456789abcdef0123456789abcdef01")
    assert fp == "ABCDEF0123456789ABCDEF0123456789ABCDEF01"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "ABCD",
        "ABCDEF0123456789ABCDEF0123456789ABCDEF",  # too short
        "G" * 40,
        "ABCDEF0123456789ABCDEF0123456789ABCDEF010",  # too long
    ],
)
def test_fingerprint_rejected(bad: str) -> None:
    with pytest.raises(GPGValidationError):
        validate_fingerprint(bad)


@pytest.mark.parametrize(
    "good",
    ["a@b.de", "alice@example.org", "name.tag+filter@sub.example.com"],
)
def test_email_accepted(good: str) -> None:
    assert validate_email(good) == good


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "no-at",
        "a@",
        "@b.de",
        "a@b",
        "a b@c.de",
        "admin|logger@example.org",
        "alice@example-.org",
    ],
)
def test_email_rejected(bad: str) -> None:
    with pytest.raises(GPGValidationError):
        validate_email(bad)


def test_user_name_rejects_angle_brackets() -> None:
    with pytest.raises(GPGValidationError):
        validate_user_name("Eve <eve@evil>")


def test_user_name_rejects_control_chars() -> None:
    with pytest.raises(GPGValidationError):
        validate_user_name("Alice\x00")


def test_user_name_rejects_unicode_and_punctuation() -> None:
    for bad in ["Müller", "Anna, Marie", "Admin --expert"]:
        with pytest.raises(GPGValidationError):
            validate_user_name(bad)


def test_user_name_accepts_strict_ascii() -> None:
    assert validate_user_name("Anna-Marie 2.0") == "Anna-Marie 2.0"


@pytest.mark.parametrize(
    ("algo", "length"),
    [
        (KeyAlgorithm.RSA, 4096),
        (KeyAlgorithm.RSA, 3072),
        (KeyAlgorithm.ECDSA, 521),
        (KeyAlgorithm.EDDSA, 255),
        (KeyAlgorithm.ECDH, 255),
    ],
)
def test_key_algorithm_length_accepted(algo: KeyAlgorithm, length: int) -> None:
    validate_key_algorithm_and_length(algo, length)


@pytest.mark.parametrize(
    ("algo", "length"),
    [
        (KeyAlgorithm.RSA, 1024),
        (KeyAlgorithm.RSA, 2049),
        (KeyAlgorithm.EDDSA, 256),
        (KeyAlgorithm.ECDSA, 1024),
    ],
)
def test_key_algorithm_length_rejected(algo: KeyAlgorithm, length: int) -> None:
    with pytest.raises(GPGValidationError):
        validate_key_algorithm_and_length(algo, length)


@pytest.mark.parametrize(
    "good", ["0", "2y", "30d", "1w", "12m", "2026-12-31"]
)
def test_expiry_accepted(good: str) -> None:
    assert validate_expiry(good) == good


def test_never_expires_is_accepted() -> None:
    """The key creation dialog's *Never* option sends "0".

    It was rejected here, so choosing *Never* produced a validation error
    instead of a key. GnuPG spells "no expiry date" exactly this way.
    """
    assert validate_expiry("0") == "0"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "0y",
        "-2y",
        "2x",
        "yesterday",
        "31-12-2026",
    ],
)
def test_expiry_rejected(bad: str) -> None:
    with pytest.raises(GPGValidationError):
        validate_expiry(bad)


def test_reject_passphrase_in_argv_passes_when_absent() -> None:
    reject_passphrase_in_argv(["--batch", "--homedir", "/tmp/x"], b"top-secret")


def test_reject_passphrase_in_argv_raises_when_present() -> None:
    with pytest.raises(GPGValidationError, match="passphrase"):
        reject_passphrase_in_argv(
            ["--batch", "--passphrase=top-secret"], b"top-secret"
        )


def test_reject_passphrase_in_argv_accepts_mutable_secret() -> None:
    with pytest.raises(GPGValidationError, match="passphrase"):
        reject_passphrase_in_argv(["--passphrase=top-secret"], bytearray(b"top-secret"))


def test_reject_passphrase_handles_empty_passphrase() -> None:
    # An empty passphrase has no leakage surface; the check should be a no-op.
    reject_passphrase_in_argv(["--anything"], b"")
