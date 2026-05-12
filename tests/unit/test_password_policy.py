from __future__ import annotations

import pytest

from gpg_meister.security.password_policy import (
    PasswordStrength,
    assess,
    require_acceptable,
)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "short",
        "abc12345",
        "passw0rd",  # too short and common-ish
    ],
)
def test_short_inputs_rejected(value: str) -> None:
    result = assess(value)
    assert not result.accepted
    assert result.strength is PasswordStrength.REJECTED or result.strength is PasswordStrength.WEAK


@pytest.mark.parametrize(
    "value",
    [
        "password",
        "PASSWORD",
        "Hunter2",
        "letmein",
        "qwerty",
        "iloveyou",
    ],
)
def test_common_passwords_rejected(value: str) -> None:
    result = assess(value)
    assert not result.accepted
    assert result.strength is PasswordStrength.REJECTED
    assert result.reason is not None


@pytest.mark.parametrize(
    "value",
    [
        "correct horse battery staple",
        "the quick brown fox jumps over the lazy dog",
        "ich liebe schokoladen kuchen sehr",
    ],
)
def test_passphrase_style_accepted(value: str) -> None:
    result = assess(value)
    assert result.accepted, f"{value!r} rejected: {result.reason}"
    assert result.strength in (PasswordStrength.ACCEPTABLE, PasswordStrength.STRONG)


@pytest.mark.parametrize(
    "value",
    [
        "Aa1!Bb2@Cc3#Dd4$",
        "MixOf4ClassesGood!",
    ],
)
def test_strong_password_accepted(value: str) -> None:
    result = assess(value)
    assert result.accepted, f"{value!r} rejected: {result.reason}"


def test_three_words_with_short_total_rejected() -> None:
    # 3 words is below the passphrase floor of 4; total length too short for password path.
    result = assess("one two three")
    assert not result.accepted


def test_require_acceptable_raises_on_weak() -> None:
    with pytest.raises(ValueError):
        require_acceptable("abc")


def test_require_acceptable_passes_on_strong() -> None:
    require_acceptable("correct horse battery staple")


def test_unicode_normalisation_does_not_break_acceptance() -> None:
    # Composed and decomposed forms of the same passphrase must produce the same
    # assessment outcome (both accepted or both rejected).
    composed = "résumé wörterbuch garten höflich"
    decomposed = "résumé wörterbuch garten höflich"
    assert assess(composed).accepted == assess(decomposed).accepted
