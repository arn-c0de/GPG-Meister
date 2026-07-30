"""Binding GPG keys to hardware tokens, and getting their passphrase back.

This is the layer where ``fido_service`` (which knows tokens but not GPG) and
``gpg_service`` (which knows GPG but not tokens) meet. It owns three things:

- **enrolment** — sealing a key's passphrase into one slot per unlock method,
- **unlocking** — turning "the token is present" back into that passphrase,
- **the ordering rules** that keep a key from ending up openable by nobody.

That last point is the whole reason this is a service and not a few functions.
A key whose passphrase exists only inside an unwritten slot is lost the instant
anything downstream fails, so the sequence is fixed: derive from the token
first, persist the slots, and only then create the key. If key creation fails,
the orphaned slots are removed. Orphaned slots are harmless; an unopenable key
is not.

Nothing here changes an existing key. A slot seals whatever passphrase the key
already has, so enrolling a token for an old key is a pure addition — no
passphrase change, no rewrite of secret-key material, nothing that could damage
a working key.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from gpg_meister.models.kdf_params import KDFParams
from gpg_meister.models.key_info import KeyAlgorithm, normalise_fingerprint
from gpg_meister.models.key_unlock import (
    FidoCredential,
    KeyUnlockSlot,
    UnlockSlotType,
    has_emergency_passphrase,
)
from gpg_meister.security.errors import DecryptionError
from gpg_meister.security.kdf import default_params
from gpg_meister.security.key_unlock import (
    check_secret,
    generate_key_secret,
    unwrap_with_passphrase,
    unwrap_with_token,
    wrap_with_passphrase,
    wrap_with_token,
)
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.errors import ServiceError
from gpg_meister.services.fido_service import (
    FidoPinError,
    FidoService,
    FidoTouchError,
    FidoUnavailableError,
)
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.storage.audit_log import OUTCOME_FAILED, OUTCOME_OK, AuditLog
from gpg_meister.storage.metadata_store import MetadataStore

# Signed during verification. Never leaves the process; only the fact that
# signing succeeded matters.
_PROBE_DATA = b"gpg-meister unlock verification"


class KeyUnlockError(ServiceError):
    """A key could not be bound to a token, or unlocked with one."""


class NoUnlockMethodError(KeyUnlockError):
    """This key has no stored unlock method of the requested kind."""


@dataclass(frozen=True)
class UnlockMethods:
    """Which ways into a key exist, readable without any credential."""

    token_labels: tuple[str, ...] = ()
    has_passphrase: bool = False

    @property
    def has_token(self) -> bool:
        return bool(self.token_labels)

    @property
    def is_token_only(self) -> bool:
        return self.has_token and not self.has_passphrase

    @property
    def is_managed(self) -> bool:
        """Whether this app holds the key's passphrase at all."""
        return self.has_token or self.has_passphrase


class KeyUnlockService:
    """Enrol tokens for GPG keys and recover their passphrases."""

    def __init__(
        self,
        *,
        gpg: GPGService,
        fido: FidoService,
        store: MetadataStore,
        audit: AuditLog | None = None,
        kdf_params: KDFParams | None = None,
    ) -> None:
        self._gpg = gpg
        self._fido = fido
        self._store = store
        self._audit = audit
        self._kdf = kdf_params or default_params()

    # ------------------------------------------------------------------ inventory

    def methods_for(self, fingerprint: str) -> UnlockMethods:
        """What can open this key, without asking for anything."""
        slots = [slot for _id, slot in self._store.unlock_slots(fingerprint)]
        return UnlockMethods(
            token_labels=tuple(
                slot.label or "Security key"
                for slot in slots
                if slot.type is UnlockSlotType.FIDO
            ),
            has_passphrase=has_emergency_passphrase(tuple(slots)),
        )

    # ----------------------------------------------------------------- enrolment

    def create_key_with_token(
        self,
        *,
        name: str,
        email: str,
        algorithm: KeyAlgorithm,
        length: int,
        expiry: str,
        pin: SecureBytes,
        emergency_passphrase: SecureBytes | None,
        on_touch: Callable[[], None] = lambda: None,
    ) -> str:
        """Create a key whose passphrase only the token (or the fallback) knows.

        ``emergency_passphrase`` may be ``None`` only when the caller has had a
        token-only key explicitly confirmed: losing the token then destroys the
        key, and nothing in this application can recover it.

        Costs two touches — one to create the credential, one to derive from it.
        """
        credential, token_secret = self._fido.enroll(
            pin=pin, user_label=f"{name} <{email}>", on_touch=on_touch
        )
        with token_secret, generate_key_secret() as secret:
            # Slots are built before the key exists so that everything that can
            # fail cheaply has failed by the time GnuPG writes secret material.
            slots = self._build_slots(secret, token_secret, credential, emergency_passphrase)
            fingerprint = self._gpg.generate_key(
                name=name,
                email=email,
                algorithm=algorithm,
                length=length,
                expiry=expiry,
                passphrase=secret,
            )
            # From here the key exists and its passphrase lives only in `secret`,
            # which is about to be wiped. If the slots cannot be stored, the key
            # is unopenable by anyone — so it is removed rather than left behind
            # as a permanent decoy in the user's keyring.
            try:
                self._persist(fingerprint, slots, event="key_created_with_token")
            except Exception:
                self._discard_unopenable_key(fingerprint, secret)
                raise
        return fingerprint

    def _discard_unopenable_key(self, fingerprint: str, secret: SecureBytes) -> None:
        """Delete a key whose passphrase was never recorded anywhere.

        Best effort: if the deletion itself fails there is nothing further to be
        done here, and the original error is the one worth reporting.
        """
        try:
            self._gpg.delete_key(fingerprint, including_secret=True, passphrase=secret)
        except Exception:
            self._emit("key_created_with_token", outcome=OUTCOME_FAILED, reason="orphan_key")

    def bind_existing_key(
        self,
        fingerprint: str,
        passphrase: SecureBytes,
        *,
        pin: SecureBytes,
        on_touch: Callable[[], None] = lambda: None,
    ) -> None:
        """Let a token open a key that already exists, leaving the key untouched.

        Only a token slot is written. No emergency slot is needed and none is
        created: the key keeps the passphrase it always had, so the way in that
        existed before still exists afterwards. Wrapping that passphrase under
        itself would store a secret the user must already know to open.

        The passphrase is verified against the key first. Storing an unverified
        one would produce a slot that hands back something GnuPG rejects — a
        failure the user would only meet later, with no way to tell it apart
        from a broken token.
        """
        fpr = normalise_fingerprint(fingerprint)
        check_secret(passphrase)
        self._verify_passphrase(fpr, passphrase)
        credential, token_secret = self._fido.enroll(
            pin=pin, user_label=fpr[-16:], on_touch=on_touch
        )
        with token_secret:
            slot = wrap_with_token(passphrase, token_secret, credential=credential)
        self._persist(fpr, [slot], event="key_bound_to_token")

    def _build_slots(
        self,
        secret: SecureBytes,
        token_secret: SecureBytes,
        credential: FidoCredential,
        emergency_passphrase: SecureBytes | None,
    ) -> list[KeyUnlockSlot]:
        slots = [wrap_with_token(secret, token_secret, credential=credential)]
        if emergency_passphrase is not None:
            slots.append(
                wrap_with_passphrase(secret, emergency_passphrase, params=self._kdf)
            )
        return slots

    def _persist(self, fingerprint: str, slots: list[KeyUnlockSlot], *, event: str) -> None:
        stored: list[int] = []
        try:
            for slot in slots:
                stored.append(self._store.add_unlock_slot(fingerprint, slot))
        except Exception:
            # All or nothing: a half-written set could leave a token-only key
            # where the user asked for a fallback.
            for slot_id in stored:
                self._store.delete_unlock_slot(slot_id)
            self._emit(event, outcome=OUTCOME_FAILED, reason="store")
            raise
        self._emit(event, outcome=OUTCOME_OK, slot_count=len(slots))

    def _verify_passphrase(self, fingerprint: str, passphrase: SecureBytes) -> None:
        """Prove the passphrase opens the key, by signing with it.

        Signing rather than exporting: both need the passphrase, only one pulls
        secret-key material into this process.
        """
        try:
            self._gpg.sign(_PROBE_DATA, fingerprint=fingerprint, passphrase=passphrase)
        except ServiceError as exc:
            raise KeyUnlockError(
                "that passphrase does not open this key, so it was not enrolled"
            ) from exc

    # ------------------------------------------------------------------ unlocking

    def unlock_with_token(
        self,
        fingerprint: str,
        *,
        pin: SecureBytes,
        on_touch: Callable[[], None] = lambda: None,
    ) -> SecureBytes:
        """Recover the key's passphrase from whichever enrolled token is present.

        Slots are tried in order, so a key enrolled with several tokens opens
        with any of them. A token that is simply not the right one is skipped;
        a wrong PIN is not, because retrying would burn the attempt counter on
        a device that was never going to work.
        """
        slots = [
            (slot_id, slot)
            for slot_id, slot in self._store.unlock_slots(fingerprint)
            if slot.type is UnlockSlotType.FIDO
        ]
        if not slots:
            raise NoUnlockMethodError("no security key is enrolled for this key")

        last_error: Exception | None = None
        for _slot_id, slot in slots:
            if slot.fido is None:  # pragma: no cover - shape is model-enforced
                continue
            try:
                with self._fido.derive(slot.fido, pin=pin, on_touch=on_touch) as token_secret:
                    secret = unwrap_with_token(slot, token_secret)
            except DecryptionError as exc:
                # The token answered but its secret does not open this slot.
                last_error = exc
                continue
            except ServiceError as exc:
                last_error = exc
                if _is_fatal_token_error(exc):
                    raise
                continue
            self._emit("key_unlocked_with_token", outcome=OUTCOME_OK)
            return secret

        self._emit("key_unlocked_with_token", outcome=OUTCOME_FAILED)
        raise KeyUnlockError(
            "no enrolled security key could open this key"
        ) from last_error

    def unlock_with_passphrase(self, fingerprint: str, passphrase: SecureBytes) -> SecureBytes:
        """Recover the key's passphrase from its emergency slot."""
        slots = [
            slot
            for _id, slot in self._store.unlock_slots(fingerprint)
            if slot.type is UnlockSlotType.PASSPHRASE and slot.kdf is not None
        ]
        if not slots:
            raise NoUnlockMethodError("this key has no passphrase fallback")
        last_error: Exception | None = None
        for slot in slots:
            if slot.kdf is None:  # pragma: no cover - filtered above
                continue
            try:
                secret = unwrap_with_passphrase(slot, passphrase, params=slot.kdf.to_params())
            except DecryptionError as exc:
                last_error = exc
                continue
            self._emit("key_unlocked_with_passphrase", outcome=OUTCOME_OK)
            return secret
        self._emit("key_unlocked_with_passphrase", outcome=OUTCOME_FAILED)
        raise KeyUnlockError("that passphrase did not open this key") from last_error

    # ------------------------------------------------------------------- removal

    def forget_key(self, fingerprint: str) -> None:
        """Drop every unlock method for a key, e.g. when the key is deleted."""
        self._store.delete_unlock_slots(fingerprint)
        self._emit("key_unlock_forgotten", outcome=OUTCOME_OK)

    def _emit(self, event: str, *, outcome: str = OUTCOME_OK, **payload: object) -> None:
        if self._audit is not None:
            self._audit.emit(event, outcome=outcome, **payload)


def _is_fatal_token_error(exc: ServiceError) -> bool:
    """Whether trying the next slot would only make things worse.

    A wrong or blocked PIN, and a token the user never touched, apply to the
    device rather than to one slot — retrying costs another PIN attempt or
    another 30-second wait for no possible gain.
    """
    return isinstance(exc, FidoPinError | FidoTouchError | FidoUnavailableError)
