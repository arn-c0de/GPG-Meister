"""Vault master passphrase strength policy.

Inline (non-modal) feedback for the user. The rules are deliberately simple — the
goal is to reject the trivially weak choices, not to enforce a specific composition.
The strongest input is a long passphrase with several unrelated words; that path is
accepted by the length-only branch without composition gymnastics.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

# Common-password starter list. A production deployment should swap in a real
# breached-password set (HIBP top-N) loaded from a data file; this in-source list
# blocks the most obvious cases without a runtime dependency.
_COMMON_PASSWORDS = frozenset(
    pw.lower()
    for pw in (
        "password",
        "passw0rd",
        "passwort",
        "123456",
        "12345678",
        "qwerty",
        "qwertz",
        "letmein",
        "iloveyou",
        "admin",
        "welcome",
        "monkey",
        "dragon",
        "baseball",
        "football",
        "test1234",
        "abc123",
        "p@ssw0rd",
        "changeme",
        "secret",
        "master",
        "sunshine",
        "princess",
        "azerty",
        "hunter2",
    )
)

MIN_PASSPHRASE_BYTES = 12
MIN_PASSWORD_BYTES = 16  # if no whitespace, demand a longer string
PASSPHRASE_WORD_PATTERN = re.compile(r"\b\w+\b", flags=re.UNICODE)


class PasswordStrength(StrEnum):
    REJECTED = "rejected"
    WEAK = "weak"
    ACCEPTABLE = "acceptable"
    STRONG = "strong"


@dataclass(frozen=True)
class PasswordAssessment:
    strength: PasswordStrength
    accepted: bool
    reason: str | None = None  # set when strength == REJECTED


def normalise_passphrase(value: str) -> str:
    return unicodedata.normalize("NFKC", value)


def _word_count(value: str) -> int:
    return len(PASSPHRASE_WORD_PATTERN.findall(value))


def _character_classes(value: str) -> int:
    classes = 0
    if any(c.islower() for c in value):
        classes += 1
    if any(c.isupper() for c in value):
        classes += 1
    if any(c.isdigit() for c in value):
        classes += 1
    if any(not c.isalnum() for c in value):
        classes += 1
    return classes


def assess(passphrase: str) -> PasswordAssessment:
    """Return an assessment for a candidate passphrase.

    The input is normalised (NFKC) but is otherwise treated opaquely. The function
    never logs or stores the value.
    """
    normalised = normalise_passphrase(passphrase)

    if len(normalised) == 0:
        return PasswordAssessment(
            strength=PasswordStrength.REJECTED,
            accepted=False,
            reason="passphrase is empty",
        )

    encoded_len = len(normalised.encode("utf-8"))

    if normalised.lower() in _COMMON_PASSWORDS:
        return PasswordAssessment(
            strength=PasswordStrength.REJECTED,
            accepted=False,
            reason="passphrase appears in a list of common passwords",
        )

    has_whitespace = any(c.isspace() for c in normalised)
    word_count = _word_count(normalised)

    # Passphrase path: at least 4 words and >= 12 UTF-8 bytes.
    if has_whitespace and word_count >= 4 and encoded_len >= MIN_PASSPHRASE_BYTES:
        return PasswordAssessment(
            strength=PasswordStrength.STRONG if encoded_len >= 24 else PasswordStrength.ACCEPTABLE,
            accepted=True,
        )

    # Password path: require length + at least 3 character classes.
    if encoded_len >= MIN_PASSWORD_BYTES and _character_classes(normalised) >= 3:
        return PasswordAssessment(
            strength=PasswordStrength.STRONG if encoded_len >= 20 else PasswordStrength.ACCEPTABLE,
            accepted=True,
        )

    if encoded_len < MIN_PASSPHRASE_BYTES:
        return PasswordAssessment(
            strength=PasswordStrength.REJECTED,
            accepted=False,
            reason=(
                f"too short — use at least 4 unrelated words or {MIN_PASSWORD_BYTES}"
                f" mixed characters"
            ),
        )

    return PasswordAssessment(
        strength=PasswordStrength.WEAK,
        accepted=False,
        reason="too easy to guess — use more words or add mixed character types",
    )


def require_acceptable(passphrase: str) -> None:
    """Raise `ValueError` if the passphrase does not pass the policy.

    Convenience for service-layer callers that simply want to gate an operation.
    """
    result = assess(passphrase)
    if not result.accepted:
        raise ValueError(result.reason or "passphrase policy violation")
