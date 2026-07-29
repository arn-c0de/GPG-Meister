"""Smartcard model, AID decoding and `gpg --card-status` parsing."""

from __future__ import annotations

from datetime import UTC, datetime

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo, KeyStorage
from gpg_meister.models.smartcard import (
    GENERIC_CARD_NAME,
    YUBIKEY_NAME,
    card_label,
    parse_aid,
    parse_card_status,
)

YUBIKEY_AID = "D2760001240103040006123456780000"
NITROKEY_AID = "D276000124010304000F987654320000"
FPR_SIG = "1111111111111111111111111111111111111111"
FPR_ENC = "2222222222222222222222222222222222222222"

CARD_STATUS = f"""\
Reader:Yubico YubiKey OTP+FIDO+CCID 00 00:AID:{YUBIKEY_AID}:openpgp-card:
version:0304:
vendor:0006:Yubico:
serial:12345678:
name:Doe:Jane:
lang:en:
sex:9:
url:https://example.org/jane.asc:
login:jane:
forcepin:0:::
keyattr:1:22:ed25519:
keyattr:2:18:cv25519:
maxpinlen:127:127:127:
pinretry:3:0:3:
sigcount:7:::
cafpr::::
fpr:{FPR_SIG}:{FPR_ENC}::
fprtime:1700000000:1700000000:0:
"""


def _key(**overrides: object) -> KeyInfo:
    base: dict[str, object] = {
        "fingerprint": "A" * 40,
        "user_ids": ("Jane <jane@example.org>",),
        "algorithm": KeyAlgorithm.EDDSA,
        "length": 255,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    base.update(overrides)
    return KeyInfo(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------- AID


def test_parse_aid_decodes_yubico_serial() -> None:
    identity = parse_aid(YUBIKEY_AID)

    assert identity.manufacturer_code == "0006"
    assert identity.manufacturer == "Yubico"
    assert identity.serial_number == "12345678"
    assert identity.version == "3.4"
    assert identity.is_yubikey


def test_parse_aid_names_other_manufacturers() -> None:
    identity = parse_aid(NITROKEY_AID)

    assert not identity.is_yubikey
    assert identity.product_name == "Nitrokey"
    assert identity.serial_number == "98765432"


def test_parse_aid_passes_through_non_aid_serials() -> None:
    identity = parse_aid("0123ABCD")

    assert identity.serial_number == "0123ABCD"
    assert identity.product_name == GENERIC_CARD_NAME


def test_card_label_is_product_plus_serial() -> None:
    assert card_label(YUBIKEY_AID) == f"{YUBIKEY_NAME} 12345678"
    assert card_label("") == GENERIC_CARD_NAME


# ------------------------------------------------------------- card status


def test_parse_card_status_reads_every_field() -> None:
    card = parse_card_status(CARD_STATUS)

    assert card is not None
    assert card.is_yubikey
    assert card.display_name == f"{YUBIKEY_NAME} 12345678"
    assert card.aid == YUBIKEY_AID
    assert card.app_type == "openpgp-card"
    assert card.reader.startswith("Yubico YubiKey")
    assert card.cardholder == "Jane Doe"
    assert card.url == "https://example.org/jane.asc"
    assert card.version == "3.4"
    assert card.pin_retries == (3, 0, 3)
    assert card.user_pin_retries == 3
    assert not card.is_pin_blocked
    assert card.key_fingerprints == (FPR_SIG, FPR_ENC)


def test_parse_card_status_reports_blocked_pin() -> None:
    card = parse_card_status(CARD_STATUS.replace("pinretry:3:0:3:", "pinretry:0:0:3:"))

    assert card is not None
    assert card.is_pin_blocked


def test_parse_card_status_without_card_returns_none() -> None:
    assert parse_card_status("") is None
    assert parse_card_status("gpg: selecting card failed\n") is None


def test_parse_card_status_survives_a_card_with_no_keys() -> None:
    card = parse_card_status(
        f"Reader:Some Reader:AID:{YUBIKEY_AID}:openpgp-card:\nserial:12345678:\n"
    )

    assert card is not None
    assert card.key_fingerprints == ()


# ------------------------------------------------------------ key storage


def test_key_on_token_reports_smartcard_storage() -> None:
    key = _key(has_private_key=True, is_stub=True, card_serial=YUBIKEY_AID)

    assert key.storage is KeyStorage.SMARTCARD
    assert key.is_on_smartcard
    assert key.storage_label == f"{YUBIKEY_NAME} 12345678"


def test_local_and_public_keys_are_not_smartcard_keys() -> None:
    local = _key(has_private_key=True)
    public = _key()

    assert local.storage is KeyStorage.LOCAL
    assert local.storage_label == "Local"
    assert not local.is_on_smartcard
    assert public.storage is KeyStorage.PUBLIC_ONLY
    assert public.storage_label == "Public only"


def test_stub_without_a_serial_is_offline_not_smartcard() -> None:
    """A `#` stub means "secret key not here" — claiming a token would mislead."""
    key = _key(has_private_key=True, is_stub=True)

    assert key.storage is KeyStorage.OFFLINE
    assert not key.is_on_smartcard
