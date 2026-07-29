"""Domain model for a GPG key as exposed to the rest of the application."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from gpg_meister.models.smartcard import card_label

FINGERPRINT_LENGTH = 40
_FINGERPRINT_CHARS = set("0123456789ABCDEF")


def normalise_fingerprint(value: str) -> str:
    """Upper-case and validate a 40-character hex fingerprint.

    Shared by every model that stores a fingerprint (``KeyInfo``,
    ``VaultKeyEntry``) so the rule lives in exactly one place.
    """
    upper = value.upper()
    if len(upper) != FINGERPRINT_LENGTH or not set(upper).issubset(_FINGERPRINT_CHARS):
        raise ValueError("fingerprint must be 40 uppercase hex characters")
    return upper


class KeyAlgorithm(StrEnum):
    RSA = "RSA"
    DSA = "DSA"
    ECDSA = "ECDSA"
    EDDSA = "EDDSA"
    ECDH = "ECDH"
    UNKNOWN = "UNKNOWN"


class TrustLevel(StrEnum):
    UNKNOWN = "unknown"
    NEVER = "never"
    MARGINAL = "marginal"
    FULL = "full"
    ULTIMATE = "ultimate"


class KeyStorage(StrEnum):
    """Where the *private* half of a key actually lives.

    ``SMARTCARD`` means at least one part of the key lives on a hardware token
    (YubiKey, Nitrokey, OpenPGP card): using it needs the token plugged in and
    its PIN, and the part held on the device can never be exported. Whether the
    *primary* key is also on the token is a separate question — ``is_stub``
    answers that, and it is what decides exportability.
    ``OFFLINE`` is GnuPG's other kind of stub — a secret key it knows about but
    does not have here (an offline primary, or a card it has not learned yet).
    """

    PUBLIC_ONLY = "public_only"
    LOCAL = "local"
    SMARTCARD = "smartcard"
    OFFLINE = "offline"


class KeyInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    fingerprint: str = Field(..., min_length=FINGERPRINT_LENGTH, max_length=FINGERPRINT_LENGTH)
    user_ids: tuple[str, ...]
    algorithm: KeyAlgorithm
    raw_algorithm_id: str = ""
    length: int = Field(..., gt=0)
    created_at: datetime
    expires_at: datetime | None = None
    is_revoked: bool = False
    has_private_key: bool = False
    is_stub: bool = False
    # Token serial (OpenPGP AID) reported by GnuPG for a smartcard-backed key;
    # empty for keys whose secret material is stored locally.
    card_serial: str = ""
    # Fingerprints of this key's subkeys. A smartcard names the *subkey* in each
    # of its slots, so matching a card against the keyring needs these.
    subkey_fingerprints: tuple[str, ...] = ()
    trust: TrustLevel = TrustLevel.UNKNOWN
    label: str = ""
    purpose: str = ""
    platform: str = ""
    notes: str = ""
    is_favorite: bool = False

    @field_validator("fingerprint")
    @classmethod
    def _validate_fingerprint(cls, value: str) -> str:
        return normalise_fingerprint(value)

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(tz=self.expires_at.tzinfo) >= self.expires_at

    @property
    def short_fingerprint(self) -> str:
        """The conventional short key id — the last 16 hex characters."""
        return self.fingerprint[-16:]

    @property
    def primary_user_id(self) -> str:
        """First user ID, falling back to the short fingerprint when there is none."""
        return self.user_ids[0] if self.user_ids else self.short_fingerprint

    @property
    def storage(self) -> KeyStorage:
        """Where the private half of this key lives (card, disk, or nowhere)."""
        if self.card_serial:
            return KeyStorage.SMARTCARD
        if self.is_stub:
            return KeyStorage.OFFLINE
        if self.has_private_key:
            return KeyStorage.LOCAL
        return KeyStorage.PUBLIC_ONLY

    @property
    def all_fingerprints(self) -> tuple[str, ...]:
        """This key's own fingerprint plus its subkeys'."""
        return (self.fingerprint, *self.subkey_fingerprints)

    @property
    def is_on_smartcard(self) -> bool:
        """True when unlocking this key needs a hardware token plus its PIN."""
        return self.storage is KeyStorage.SMARTCARD

    @property
    def storage_label(self) -> str:
        """Column/badge text: ``YubiKey 12345678``, ``Local``, ``Public only``."""
        return {
            KeyStorage.SMARTCARD: card_label(self.card_serial),
            KeyStorage.OFFLINE: "Secret key elsewhere",
            KeyStorage.LOCAL: "Local",
            KeyStorage.PUBLIC_ONLY: "Public only",
        }[self.storage]

    @property
    def display_label(self) -> str:
        """Combo/list label, e.g. ``Alice <a@example.com>  [0123ABCD4567EF89]``.

        Decorations like a private-key star or a stub prefix are left to the
        call site; this is just the shared base text.
        """
        return f"{self.primary_user_id}  [{self.short_fingerprint}]"
