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
- **Administration.** PIN changes, unblocking, moving a key onto the card, and
  generating one there. These drive GnuPG's interactive editors through scripted
  answers (see ``card_scripts``) and are the only operations here that can
  destroy key material, so each one refuses to touch an occupied card slot
  unless the caller passes an explicit overwrite flag.

Unlocking itself needs nothing special: with loopback pinentry the card PIN is
answered from the same ``--passphrase-fd`` pipe as a normal key passphrase (see
``gpg_service``), so decrypt/sign/encrypt-and-sign work unchanged once the stubs
are in place.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.models.smartcard import CardInfo, CardPin, CardSlot, parse_card_status
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.card_scripts import (
    PromptScript,
    card_operation_failed,
    change_pin_script,
    generate_on_card_script,
    keytocard_script,
    unblock_pin_script,
)
from gpg_meister.services.errors import GPGCardError, GPGCardPinError, GPGServiceError
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.services.validation import (
    validate_email,
    validate_expiry,
    validate_fingerprint,
    validate_user_name,
)
from gpg_meister.storage.audit_log import (
    OUTCOME_FAILED,
    OUTCOME_OK,
    AuditLog,
    emit_best_effort,
)

# Why GnuPG found no card, in the order the checks have to run: the daemon
# message also mentions "not available", so it must be matched first. Each entry
# maps a fragment of gpg's stderr to something the user can act on.
_UNAVAILABLE_REASONS: tuple[tuple[str, str], ...] = (
    (
        "no smartcard daemon",
        "GnuPG's smartcard daemon is missing. Install the 'scdaemon' package "
        "(on Debian/Ubuntu: sudo apt install scdaemon), then plug the token in again.",
    ),
    (
        "no card reader",
        "No smartcard reader was found. If the token is plugged in, its smartcard "
        "interface may be switched off — check with 'ykman info'.",
    ),
    (
        "no such device",
        "A reader is present but no card responded. If this is a YubiKey, its CCID "
        "(smartcard) interface may be disabled — check with 'ykman info'.",
    ),
    (
        "selecting card failed",
        "The card could not be selected. Another program may be holding it — close "
        "other GnuPG or smartcard applications and try again.",
    ),
    (
        "card error",
        "The reader reported a card error. Re-insert the token and try again.",
    ),
)


def _unavailable_reason(diagnostics: str) -> str:
    """Translate gpg's complaint into something the user can act on."""
    lowered = diagnostics.lower()
    for marker, reason in _UNAVAILABLE_REASONS:
        if marker in lowered:
            return reason
    return ""


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
    # Why no card was found, when GnuPG said something useful about it.
    unavailable_reason: str = ""

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
        """Return the inserted card, or ``None`` when no token is reachable."""
        return self.probe()[0]

    def probe(self) -> tuple[CardInfo | None, str]:
        """Return the inserted card and, when there is none, why not.

        Never raises for "there is no card": absence is the common case and the
        UI polls this on every refresh. The reason matters because the causes
        look identical from the outside — a missing ``scdaemon`` package, a
        token whose smartcard interface is switched off, and an empty reader all
        produce "no card" while needing completely different fixes.
        """
        try:
            output = self._gpg.card_status()
        except GPGCardError as exc:
            # Match on GnuPG's own diagnostics, not on the exception message: by
            # the time it is raised the message has been normalised to "no
            # smartcard is available", which every marker below would miss.
            return None, _unavailable_reason(exc.diagnostics or str(exc))
        except GPGServiceError:
            # A broken reader/scdaemon setup must not take the Keys tab down.
            return None, ""
        card = parse_card_status(output.colons)
        if card is None:
            return None, _unavailable_reason(output.diagnostics)
        return card, ""

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
            card, reason = self.probe()
            keys = self.card_keys()
        except Exception as exc:
            self._emit("smartcard_keys_synced", outcome=OUTCOME_FAILED, reason=type(exc).__name__)
            raise

        if card is None:
            self._emit("smartcard_detected", outcome=OUTCOME_OK, card_present="False")
            return CardSyncResult(keys=tuple(keys), unavailable_reason=reason)

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

    # ----------------------------------------------------------- card admin

    def change_pin(self, pin: CardPin, *, current: SecureBytes, new: SecureBytes) -> None:
        """Change the card's user or admin PIN.

        Wrong attempts count against the card's retry counter, so the caller
        should show the remaining attempts before letting the user try again.
        """
        self._run_card_script(
            ["--card-edit"],
            change_pin_script(pin, current=current, new=new),
            operation=f"{pin.value} PIN change",
            event="smartcard_pin_changed",
        )

    def unblock_user_pin(self, *, admin_pin: SecureBytes, new_user_pin: SecureBytes) -> None:
        """Reset a blocked user PIN with the admin PIN."""
        self._run_card_script(
            ["--card-edit"],
            unblock_pin_script(admin_pin=admin_pin, new_user_pin=new_user_pin),
            operation="PIN unblock",
            event="smartcard_pin_changed",
        )

    def move_key_to_card(
        self,
        fingerprint: str,
        slot: CardSlot,
        *,
        key_passphrase: SecureBytes,
        admin_pin: SecureBytes,
        key_index: int = 0,
        allow_overwrite: bool = False,
    ) -> None:
        """Move a local key onto the card. **The local secret key is replaced.**

        GnuPG turns the on-disk secret key into a stub pointing at the card, so
        the only remaining copy is the one on the token (and whatever backup the
        user made beforehand). Refuses to overwrite a populated slot unless
        ``allow_overwrite`` says the user was told what is in it.
        """
        fp = validate_fingerprint(fingerprint)
        if key_index < 0:
            raise GPGCardError("invalid subkey selection")
        self._require_free_slot(slot, allow_overwrite=allow_overwrite)
        self._run_card_script(
            ["--edit-key", fp],
            keytocard_script(
                slot,
                key_index=key_index,
                key_passphrase=key_passphrase,
                admin_pin=admin_pin,
            ),
            operation="moving the key onto the card",
            event="smartcard_key_moved",
            fingerprint=fp,
            slot=slot.value,
        )

    def generate_key_on_card(
        self,
        *,
        admin_pin: SecureBytes,
        user_pin: SecureBytes,
        name: str,
        email: str,
        expiry: str = "0",
        off_card_backup: bool = True,
        allow_overwrite: bool = False,
    ) -> None:
        """Generate a new key set on the card itself.

        The private keys are created on the device and can never be read back,
        so ``off_card_backup`` (GnuPG's off-card backup of the *encryption* key)
        is on by default: without it, a lost card means encrypted data is gone.
        Overwriting a populated card needs ``allow_overwrite``.
        """
        clean_name = validate_user_name(name)
        clean_email = validate_email(email)
        # "0" is GnuPG's own answer for "does not expire"; every other form goes
        # through the shared validator.
        if expiry != "0":
            validate_expiry(expiry)
        if not allow_overwrite:
            card = self.detect()
            if card is not None and card.occupied_slots():
                raise GPGCardError(
                    "this card already holds keys — generating new ones would destroy them"
                )
        self._run_card_script(
            ["--card-edit"],
            generate_on_card_script(
                admin_pin=admin_pin,
                user_pin=user_pin,
                name=clean_name,
                email=clean_email,
                expiry=expiry,
                off_card_backup=off_card_backup,
                replace_existing=allow_overwrite,
            ),
            operation="generating keys on the card",
            event="smartcard_key_generated",
        )

    def _require_free_slot(self, slot: CardSlot, *, allow_overwrite: bool) -> None:
        if allow_overwrite:
            return
        card = self.detect()
        if card is None:
            raise GPGCardError("no smartcard is available — insert your token and try again")
        if card.slot_fingerprint(slot):
            raise GPGCardError(
                f"the {slot.slot_name.lower()} slot already holds a key; "
                "overwriting it would destroy that key"
            )

    def _run_card_script(
        self,
        args: list[str],
        script: PromptScript,
        *,
        operation: str,
        event: str,
        **payload: object,
    ) -> None:
        """Execute a scripted editor session and translate its outcome.

        The script is wiped whatever happens, so the PINs it carries do not
        outlive the call.
        """
        try:
            result = self._gpg.run_prompt_script(args, script)
            leftover = script.pending()
        finally:
            script.wipe()

        if result.unanswered_prompt is not None:
            self._emit(event, outcome=OUTCOME_FAILED, reason="unexpected_prompt", **payload)
            # Deliberately not "nothing was changed": the run was cut off part
            # way through a menu, and only the card itself can say how far it
            # got. Point at the refresh instead of making a promise.
            raise GPGCardError(
                f"{operation} was stopped: this GnuPG version asked something unexpected "
                f"({result.unanswered_prompt}). Check the card status before retrying, and "
                "use `gpg --card-edit` in a terminal for this operation."
            )

        stderr = result.stderr.decode("utf-8", errors="replace")
        failure = card_operation_failed(result.status_records())
        if failure is not None or result.returncode != 0:
            self._emit(event, outcome=OUTCOME_FAILED, reason=failure or "process", **payload)
            lowered = stderr.lower()
            if "pin" in lowered and ("bad" in lowered or "wrong" in lowered or "block" in lowered):
                raise GPGCardPinError(f"{operation} failed: the card rejected the PIN")
            raise GPGCardError(f"{operation} failed: {stderr[:200] or failure}")

        # Leftover answers mean GnuPG asked fewer questions than scripted — it
        # skipped a submenu, say. That is *not* treated as failure: GnuPG
        # reported no error, and crying failure over a change that may well have
        # happened would push the user into a retry that burns PIN attempts with
        # a PIN that is no longer current. It is recorded instead.
        self._emit(
            event,
            outcome=OUTCOME_OK,
            unused_answers=len(leftover),
            **payload,
        )

    def _emit(self, event: str, *, outcome: str = OUTCOME_OK, **payload: object) -> None:
        # Best-effort: a PIN change or a key move on the card cannot be undone
        # by failing to write the line that says it happened.
        emit_best_effort(self._audit, event, outcome=outcome, **payload)
