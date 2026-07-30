"""Smartcard-related parsing in the GPG adapter (no GnuPG process involved)."""

from __future__ import annotations

import pytest

from gpg_meister.services.errors import GPGCardError, GPGCardPinError
from gpg_meister.services.gpg_service import (
    _card_diagnosis,
    _parse_colons_keys,
    _raise_for_card_failure,
    _to_key_info,
    _token_state,
)

YUBIKEY_AID = "D2760001240103040006123456780000"
PRIMARY_FPR = "59F67CFC0C6A8634CD2E7FF2B9935D826E873EBB"
SUB_FPR = "2F390C846095D688CD193C0A5B493B7144AE5423"

LOCAL_SECRET_LISTING = f"""\
sec:u:255:22:B9935D826E873EBB:1785349712:1816885712::u:::scESC:::+::ed25519:::0:
fpr:::::::::{PRIMARY_FPR}:
uid:u::::1785349712::AAAA::Alice <alice@example.org>::::::::::0:
ssb:u:255:18:5B493B7144AE5423:1785349712::::::e:::+::cv25519::
fpr:::::::::{SUB_FPR}:
""".encode()

CARD_SECRET_LISTING = f"""\
sec:u:255:22:B9935D826E873EBB:1785349712:1816885712::u:::scESC:::#::ed25519:::0:
fpr:::::::::{PRIMARY_FPR}:
uid:u::::1785349712::AAAA::Alice <alice@example.org>::::::::::0:
ssb:u:255:18:5B493B7144AE5423:1785349712::::::e:::{YUBIKEY_AID}::cv25519::
fpr:::::::::{SUB_FPR}:
""".encode()

# Primary key still on disk, only the encryption subkey moved to the card.
HYBRID_SECRET_LISTING = CARD_SECRET_LISTING.replace(b"scESC:::#:", b"scESC:::+:")


# ------------------------------------------------------------- field 15


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("+", ("", False)),
        ("", ("", False)),
        ("#", ("", True)),
        (YUBIKEY_AID, (YUBIKEY_AID, True)),
    ],
)
def test_token_state_distinguishes_markers_from_serials(
    raw: str, expected: tuple[str, bool]
) -> None:
    assert _token_state(raw) == expected


def test_local_secret_key_is_not_reported_as_a_stub() -> None:
    """`+` means "the secret key is right here" — the opposite of a stub."""
    rows = _parse_colons_keys(LOCAL_SECRET_LISTING)
    key = _to_key_info(rows[0])

    assert key.fingerprint == PRIMARY_FPR
    assert not key.is_stub
    assert key.card_serial == ""
    assert not key.is_on_smartcard


def test_subkey_token_serial_marks_the_primary_key_as_card_backed() -> None:
    """The usual YubiKey layout: offline primary, encryption subkey on the card."""
    rows = _parse_colons_keys(CARD_SECRET_LISTING)
    key = _to_key_info(rows[0])

    assert key.fingerprint == PRIMARY_FPR
    assert key.card_serial == YUBIKEY_AID
    assert key.is_on_smartcard
    assert key.storage_label == "YubiKey 12345678"


def test_a_primary_key_still_on_disk_stays_exportable() -> None:
    """Only the primary record decides whether secret material can be exported.

    With just the encryption subkey moved to a token, the primary key is still
    on disk — treating the whole key as a stub would silently reduce a vault
    backup to the public key.
    """
    key = _to_key_info(_parse_colons_keys(HYBRID_SECRET_LISTING)[0])

    assert not key.is_stub
    assert key.card_serial == YUBIKEY_AID
    assert key.is_on_smartcard


def test_subkey_fingerprints_are_kept_apart_from_the_primary() -> None:
    """A card names the key in each slot by the subkey's fingerprint."""
    key = _to_key_info(_parse_colons_keys(CARD_SECRET_LISTING)[0])

    assert key.fingerprint == PRIMARY_FPR
    assert key.subkey_fingerprints == (SUB_FPR,)
    assert key.all_fingerprints == (PRIMARY_FPR, SUB_FPR)


# ------------------------------------------------------- failure diagnosis


def test_missing_card_status_record_is_diagnosed() -> None:
    diagnosis = _card_diagnosis([["CARDCTRL", "5"]], "")

    assert diagnosis is not None
    assert diagnosis[0] is GPGCardError


def test_stderr_marker_is_diagnosed_when_no_status_record_exists() -> None:
    diagnosis = _card_diagnosis([], "gpg: public key decryption failed: No such device")

    assert diagnosis is not None
    assert diagnosis[0] is GPGCardError


def test_pin_failure_is_distinguished_from_a_missing_card() -> None:
    diagnosis = _card_diagnosis([], "gpg: signing failed: Bad PIN")

    assert diagnosis is not None
    assert diagnosis[0] is GPGCardPinError


def test_ordinary_passphrase_failure_is_not_a_card_problem() -> None:
    assert _card_diagnosis([], "gpg: decryption failed: Bad passphrase") is None
    _raise_for_card_failure([], "gpg: decryption failed: No secret key", operation="decryption")


def test_raise_for_card_failure_reports_the_operation() -> None:
    with pytest.raises(GPGCardError, match="decryption failed"):
        _raise_for_card_failure([["CARDCTRL", "1"]], "", operation="decryption")


def test_the_raised_error_carries_gpgs_own_words() -> None:
    """The message is normalised for display; the detail must not be lost with it.

    "no smartcard is available" covers a missing scdaemon package, a token with
    its CCID interface switched off, and an empty reader alike — and each needs
    a different fix, so the caller needs the original text to tell them apart.
    """
    diagnostics = "gpg: OpenPGP card not available: No SmartCard daemon\n"

    with pytest.raises(GPGCardError) as excinfo:
        _raise_for_card_failure([], diagnostics, operation="card status")

    assert excinfo.value.diagnostics == diagnostics
