"""Domain model for an OpenPGP smartcard (YubiKey, Nitrokey, OpenPGP card, …).

Everything here is pure data + parsing so it can be unit-tested without GnuPG.
Two independent sources feed these models:

- ``gpg --card-status --with-colons`` describes the *inserted* card (reader,
  serial, cardholder, PIN retry counters, the fingerprints of the keys stored in
  the card's three slots). :func:`parse_card_status` turns that into a
  :class:`CardInfo`.
- ``gpg --list-secret-keys --with-colons`` field 15 carries the token serial
  number for every secret key that is only a *stub* pointing at a card. That
  serial is an OpenPGP AID, which :func:`parse_aid` decodes.

The AID layout (OpenPGP card spec §4.2.1) is 16 bytes / 32 hex characters::

    D2 76 00 01 24 01 | VV VV | MM MM | SS SS SS SS | 00 00
    └── RID ────────┘   version  manuf.  serial no.    RFU
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import unquote

# Registered application provider identifier of the OpenPGP card application.
OPENPGP_RID = "D276000124"
_AID_LENGTH = 32
_HEX_CHARS = frozenset("0123456789ABCDEF")

# Manufacturer ids assigned by the OpenPGP card spec (GnuPG's app-openpgp.c
# get_manufacturer()). Only the ones a user is realistically holding are listed;
# anything else falls back to the generic label.
_MANUFACTURERS: dict[str, str] = {
    "0001": "PPC Card Systems",
    "0002": "Prism",
    "0003": "OpenFortress",
    "0004": "Wewid",
    "0005": "ZeitControl",
    "0006": "Yubico",
    "0007": "OpenKMS",
    "0008": "LogoEmail",
    "0009": "Fidesmo",
    "000A": "VivoKey",
    "000B": "Trustica",
    "000D": "Dangerous Things",
    "000E": "Excelsecu",
    "000F": "Nitrokey",
    "002A": "Magrathea",
    "0042": "GnuPG e.V.",
    "1337": "Warsaw Hackerspace",
    "2342": "warpzone",
    "4354": "Confidential Technologies",
    "5443": "TIF-IT",
    "63AF": "Trustica",
    "BA53": "c-base",
    "BD0E": "Paranoidlabs",
    "F517": "FSIJ",
    "F5EC": "F-Secure",
}

YUBICO_MANUFACTURER = "0006"
GENERIC_CARD_NAME = "Smartcard"
YUBIKEY_NAME = "YubiKey"


@dataclass(frozen=True)
class CardIdentity:
    """The decoded parts of an OpenPGP AID."""

    version: str = ""
    manufacturer_code: str = ""
    serial_number: str = ""

    @property
    def manufacturer(self) -> str:
        return _MANUFACTURERS.get(self.manufacturer_code.upper(), "")

    @property
    def is_yubikey(self) -> bool:
        return self.manufacturer_code.upper() == YUBICO_MANUFACTURER

    @property
    def product_name(self) -> str:
        """``YubiKey``, a known manufacturer name, or the generic fallback."""
        if self.is_yubikey:
            return YUBIKEY_NAME
        return self.manufacturer or GENERIC_CARD_NAME


def parse_aid(serial: str) -> CardIdentity:
    """Decode an OpenPGP AID such as ``D2760001240103040006123456780000``.

    Anything that is not a 32-character OpenPGP AID (a short serial printed by
    ``--card-status``, a vendor-specific token id, an empty string) is returned
    as a bare serial number so callers still have something to display.
    """
    raw = serial.strip().upper()
    if not raw:
        return CardIdentity()
    if len(raw) == _AID_LENGTH and raw.startswith(OPENPGP_RID) and set(raw) <= _HEX_CHARS:
        return CardIdentity(
            version=f"{int(raw[12:14])}.{int(raw[14:16])}",
            manufacturer_code=raw[16:20],
            serial_number=raw[20:28],
        )
    return CardIdentity(serial_number=raw)


def card_label(serial: str) -> str:
    """Short human label for a token serial, e.g. ``YubiKey 12345678``.

    Used for the key-list storage column and every "which device holds this
    key" hint in the UI.
    """
    identity = parse_aid(serial)
    if not identity.serial_number:
        return GENERIC_CARD_NAME
    return f"{identity.product_name} {identity.serial_number}"


@dataclass(frozen=True)
class CardInfo:
    """A card that is currently plugged in, as reported by ``gpg --card-status``."""

    serial: str = ""
    aid: str = ""
    reader: str = ""
    app_type: str = ""
    version: str = ""
    manufacturer_code: str = ""
    manufacturer: str = ""
    cardholder: str = ""
    url: str = ""
    login: str = ""
    # PIN retry counters in GnuPG's order: user PIN, reset code, admin PIN.
    # -1 means "not reported by this card / GnuPG version".
    pin_retries: tuple[int, int, int] = (-1, -1, -1)
    # Fingerprints of the keys in the signature / encryption / authentication
    # slots. Empty strings mark unused slots.
    slot_fingerprints: tuple[str, str, str] = ("", "", "")
    key_attributes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def identity(self) -> CardIdentity:
        """AID-derived identity, falling back to the short ``serial:`` field."""
        decoded = parse_aid(self.aid or self.serial)
        if decoded.manufacturer_code or not self.manufacturer_code:
            return decoded
        return CardIdentity(
            version=decoded.version or self.version,
            manufacturer_code=self.manufacturer_code,
            serial_number=decoded.serial_number,
        )

    @property
    def is_yubikey(self) -> bool:
        return self.identity.is_yubikey or self.manufacturer_code.upper() == YUBICO_MANUFACTURER

    @property
    def product_name(self) -> str:
        if self.is_yubikey:
            return YUBIKEY_NAME
        return self.manufacturer or self.identity.product_name

    @property
    def short_serial(self) -> str:
        return self.identity.serial_number or self.serial

    @property
    def display_name(self) -> str:
        """e.g. ``YubiKey 12345678`` — what the UI puts in front of the user."""
        serial = self.short_serial
        return f"{self.product_name} {serial}".strip() if serial else self.product_name

    @property
    def user_pin_retries(self) -> int:
        return self.pin_retries[0]

    @property
    def admin_pin_retries(self) -> int:
        return self.pin_retries[2]

    @property
    def is_pin_blocked(self) -> bool:
        return self.user_pin_retries == 0

    @property
    def key_fingerprints(self) -> tuple[str, ...]:
        """Fingerprints present in any slot, de-duplicated, order preserved."""
        seen: list[str] = []
        for fpr in self.slot_fingerprints:
            if fpr and fpr not in seen:
                seen.append(fpr)
        return tuple(seen)


def _split_record(line: str) -> tuple[str, list[str]]:
    fields = line.split(":")
    return fields[0].strip().lower(), [f.strip() for f in fields[1:]]


def _single_value(line: str) -> str:
    """The whole value of a one-field record, colons and all.

    A URL is the one card field that routinely contains ``:``, so it cannot be
    read as "the text up to the next separator". GnuPG percent-escapes control
    characters in colon listings, so the value is unescaped here as well.
    """
    _, _, rest = line.partition(":")
    return unquote(rest.strip().removesuffix(":").strip())


def _field(values: list[str], index: int) -> str:
    return values[index] if index < len(values) else ""


def _retry_counters(values: list[str]) -> tuple[int, int, int]:
    counters: list[int] = []
    for index in range(3):
        raw = _field(values, index)
        counters.append(int(raw) if raw.lstrip("-").isdigit() else -1)
    return (counters[0], counters[1], counters[2])


def _normalise_fpr(value: str) -> str:
    cleaned = value.replace(" ", "").upper()
    return cleaned if cleaned and set(cleaned) <= _HEX_CHARS else ""


def _card_version(raw: str) -> str:
    """``0304`` → ``3.4``; anything unexpected is passed through unchanged."""
    if len(raw) == 4 and raw.isdigit():
        return f"{int(raw[:2])}.{int(raw[2:4])}"
    return raw


def _reader_aid(values: list[str]) -> tuple[str, str]:
    """``Reader:<name>:AID:<aid>:<apptype>:`` — the AID/apptype tail is optional."""
    for index, value in enumerate(values):
        if value.upper() == "AID":
            return _field(values, index + 1).upper(), _field(values, index + 2)
    candidate = _field(values, 1).upper()
    if len(candidate) == _AID_LENGTH and set(candidate) <= _HEX_CHARS:
        return candidate, ""
    return "", ""


def _cardholder(surname: str, given: str) -> str:
    """GnuPG stores the name as ``Surname<<Given``; join it the way people read it."""
    parts = (given, surname)
    return " ".join(part.replace("<", " ").strip() for part in parts if part).strip()


def parse_card_status(output: str) -> CardInfo | None:
    """Parse ``gpg --card-status --with-colons`` output.

    Returns ``None`` when the output carries no card record at all (no reader,
    no serial), which is how GnuPG reports "nothing plugged in" on some
    platforms instead of failing outright.
    """
    reader = serial = aid = app_type = version = ""
    manufacturer_code = manufacturer = url = login = ""
    surname = given = ""
    pin_retries: tuple[int, int, int] = (-1, -1, -1)
    slot_fingerprints: tuple[str, str, str] = ("", "", "")
    key_attributes: list[str] = []

    for raw_line in output.splitlines():
        if ":" not in raw_line:
            continue
        record, values = _split_record(raw_line)
        if record == "reader":
            reader = _field(values, 0)
            reader_aid, reader_app = _reader_aid(values)
            aid = aid or reader_aid
            app_type = app_type or reader_app
        elif record == "serial":
            serial = _field(values, 0).upper()
        elif record == "aid":
            aid = _field(values, 0).upper()
        elif record == "apptype":
            app_type = _field(values, 0)
        elif record == "version":
            version = _card_version(_field(values, 0))
        elif record == "vendor":
            manufacturer_code = _field(values, 0).upper()
            manufacturer = _field(values, 1)
        elif record == "name":
            surname, given = _field(values, 0), _field(values, 1)
        elif record == "url":
            url = _single_value(raw_line)
        elif record == "login":
            login = _field(values, 0)
        elif record == "pinretry":
            pin_retries = _retry_counters(values)
        elif record == "fpr":
            slot_fingerprints = (
                _normalise_fpr(_field(values, 0)),
                _normalise_fpr(_field(values, 1)),
                _normalise_fpr(_field(values, 2)),
            )
        elif record == "keyattr":
            key_attributes.append(":".join(value for value in values if value))

    if not (serial or aid or reader):
        return None

    return CardInfo(
        serial=serial,
        aid=aid,
        reader=reader,
        app_type=app_type,
        version=version,
        manufacturer_code=manufacturer_code,
        manufacturer=manufacturer,
        cardholder=_cardholder(surname, given),
        url=url,
        login=login,
        pin_retries=pin_retries,
        slot_fingerprints=slot_fingerprints,
        key_attributes=tuple(key_attributes),
    )
