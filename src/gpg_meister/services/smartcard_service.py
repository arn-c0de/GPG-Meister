"""Smartcard (YubiKey / Nitrokey / OpenPGP card) support.

GnuPG already knows how to drive an OpenPGP token; what this service adds is the
part the application needs on top:

- **Presence.** :meth:`SmartcardService.detect` reports the inserted card without
  raising, so the UI can show "YubiKey 12345678 connected" or "no token" as a
  normal state rather than an error.
- **Learning.** GPG Meister runs GnuPG against its *own* ``--homedir``, so the
  card's secret-key stubs do not exist there until GnuPG has seen the token
  once. :meth:`SmartcardService.sync` performs that learn step and reports which
  card keys became usable and which still need their public key imported.
- **Inventory.** :meth:`SmartcardService.card_keys` lists the keys in the keyring
  whose private half lives on a token, which drives the storage labels and the
  "enter your PIN, not a passphrase" hints.

Unlocking itself needs nothing special: with loopback pinentry the card PIN is
answered from the same ``--passphrase-fd`` pipe as a normal key passphrase (see
``gpg_service``), so decrypt/sign/encrypt-and-sign work unchanged once the stubs
are in place.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.models.smartcard import CardInfo, parse_card_status
from gpg_meister.services.errors import GPGCardError, GPGServiceError
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.storage.audit_log import OUTCOME_FAILED, OUTCOME_OK, AuditLog


@dataclass(frozen=True)
class CardSyncResult:
    """Outcome of a learn step against the inserted card."""

    card: CardInfo | None = None
    # Card keys the keyring can now use (a stub exists for them).
    linked_fingerprints: tuple[str, ...] = ()
    # Card keys whose public key is missing locally, so GnuPG cannot create a
    # stub for them. The user has to import the public key first.
    missing_fingerprints: tuple[str, ...] = ()
    keys: tuple[KeyInfo, ...] = field(default_factory=tuple)

    @property
    def card_present(self) -> bool:
        return self.card is not None

    @property
    def needs_public_key_import(self) -> bool:
        return bool(self.missing_fingerprints)


class SmartcardService:
    def __init__(self, *, gpg: GPGService, audit: AuditLog | None = None) -> None:
        self._gpg = gpg
        self._audit = audit

    # ------------------------------------------------------------------ presence

    def detect(self) -> CardInfo | None:
        """Return the inserted card, or ``None`` when no token is reachable.

        Never raises for "there is no card": absence is the common case and the
        UI polls this on every refresh.
        """
        try:
            output = self._gpg.card_status()
        except GPGCardError:
            return None
        except GPGServiceError:
            # A broken reader/scdaemon setup must not take the Keys tab down.
            return None
        return parse_card_status(output)

    # ----------------------------------------------------------------- inventory

    def card_keys(self) -> list[KeyInfo]:
        """Keys in the keyring whose private half lives on a hardware token."""
        return [key for key in self._gpg.list_keys(secret=True) if key.is_on_smartcard]

    def has_card_keys(self) -> bool:
        return bool(self.card_keys())

    # ---------------------------------------------------------------------- sync

    def sync(self) -> CardSyncResult:
        """Make GnuPG learn the inserted card and report what is usable now.

        ``gpg --card-status`` creates a secret-key stub for every card key whose
        public key is already in this keyring; keys without a local public key
        are reported in ``missing_fingerprints`` so the UI can send the user to
        the public-key import (the card's ``url`` often points at it).
        """
        try:
            card = self.detect()
            keys = self.card_keys()
        except Exception as exc:
            self._emit("smartcard_keys_synced", outcome=OUTCOME_FAILED, reason=type(exc).__name__)
            raise

        if card is None:
            self._emit("smartcard_detected", outcome=OUTCOME_OK, card_present="False")
            return CardSyncResult(keys=tuple(keys))

        # A card names the key in each slot by *its own* fingerprint, which for
        # the usual layout is a subkey — so the keyring is indexed by primary and
        # subkey fingerprints alike, or every correctly linked card key would be
        # reported as missing.
        known = {fpr for key in keys for fpr in key.all_fingerprints}
        linked = tuple(fpr for fpr in card.key_fingerprints if fpr in known)
        missing = tuple(fpr for fpr in card.key_fingerprints if fpr not in known)
        self._emit(
            "smartcard_keys_synced",
            outcome=OUTCOME_OK,
            linked_count=len(linked),
            missing_count=len(missing),
        )
        return CardSyncResult(
            card=card,
            linked_fingerprints=linked,
            missing_fingerprints=missing,
            keys=tuple(keys),
        )

    def _emit(self, event: str, *, outcome: str = OUTCOME_OK, **payload: object) -> None:
        if self._audit is not None:
            self._audit.emit(event, outcome=outcome, **payload)
