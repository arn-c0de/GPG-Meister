"""FIDO2 hardware tokens as a way to unlock a local GPG key.

This is the counterpart to ``smartcard_service`` for tokens that have no OpenPGP
applet at all — the FIDO-only devices, such as Yubico's Security Key Series.
Such a token cannot *hold* a GPG key, so nothing here talks to GnuPG. What it
can do is derive a secret that only it can reproduce, through the WebAuthn
``prf`` extension (CTAP2 ``hmac-secret`` underneath): give the same credential
the same salt and it returns the same 32 bytes, forever, and no copy of them
exists anywhere else.

``services.key_unlock_service`` turns that into an unlock method by sealing the
key's passphrase under those bytes.

**Why ``prf`` and not raw ``hmac-secret``.** They are the same authenticator
feature, but the ``prf`` layer hashes the salt client-side before passing it
down, so the two produce *different* outputs from the same token and the same
salt. Every enrolled credential in the wild depends on this choice, so it is
fixed here and must never be revisited: ``prf``, always.

**Where the PIN lives.** Everything else in this application keeps secrets in
``SecureBytes`` and never lets them become Python ``str``. That is not
achievable here: ``python-fido2`` takes the PIN as ``str``, and Python strings
are immutable and cannot be wiped. The PIN is therefore decoded as late as
possible, immediately before the library call, and the caller's ``SecureBytes``
remains the only long-lived copy. This is a real, documented narrowing of the
guarantee, limited to the FIDO PIN — the GPG passphrase path is untouched.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import Callable
from dataclasses import dataclass

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2
from fido2.hid import CtapHidDevice
from fido2.webauthn import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialType,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from gpg_meister.models.key_unlock import PRF_SALT_LEN, FidoCredential
from gpg_meister.security.key_unlock import TOKEN_SECRET_LEN
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object
from gpg_meister.services.errors import ServiceError
from gpg_meister.storage.audit_log import OUTCOME_FAILED, OUTCOME_OK, AuditLog

# The relying-party id every credential is bound to. It is never resolved over
# the network — it exists only to scope credentials to this application. It must
# never change: a different value makes every enrolled token unable to find its
# credential, which is indistinguishable from a lost token.
RP_ID = "gpg-meister.local"
_ORIGIN = f"https://{RP_ID}"

# ECDSA-P256 and Ed25519. Any FIDO2 authenticator supports at least the first.
_ALGORITHMS = (-7, -8)


class FidoServiceError(ServiceError):
    """A hardware-token operation could not be completed."""


class FidoUnavailableError(FidoServiceError):
    """No usable FIDO2 token is reachable right now."""


class FidoPinError(FidoServiceError):
    """The token's PIN was wrong, missing, or locked out."""


class FidoTouchError(FidoServiceError):
    """The token was never touched, so it refused the operation."""


class FidoCredentialError(FidoServiceError):
    """This token does not hold the credential the key was enrolled with."""


@dataclass(frozen=True)
class TokenInfo:
    """What is known about the plugged-in token without touching it."""

    product_name: str
    has_pin: bool
    supports_prf: bool
    supports_resident_keys: bool

    @property
    def is_usable(self) -> bool:
        return self.supports_prf


# Why no token is usable, in the order the checks must run. Each entry says what
# the user can actually do about it, because these causes look identical from
# the outside — the same "nothing happened" for a missing device, a blocked
# device node, and a token that lacks the feature entirely.
_NO_TOKEN = (
    "No security key found. Plug your token into a USB port and try again."  # noqa: S105
)
_NO_ACCESS = (
    "A security key is present but this user cannot open it. On Linux the FIDO "
    "udev rules are missing — install the 'libfido2' package (which ships them) "
    "or add a rule granting access to /dev/hidraw*, then re-plug the token."
)
_NO_PRF = (
    "This token cannot derive secrets: it does not support the FIDO2 "
    "'hmac-secret' extension, which unlocking a key with it requires."
)


def _translate(exc: CtapError) -> FidoServiceError:
    """Turn a CTAP status into something the user can act on.

    ``OPERATION_DENIED`` is the one worth spelling out: a YubiKey reports "you
    never touched me" with the same code it uses for a genuine refusal, so
    without this mapping a missed touch reads as a hardware fault.
    """
    code = exc.code
    err = CtapError.ERR
    if code in (err.PIN_INVALID, err.PIN_AUTH_INVALID):
        return FidoPinError("the token rejected the PIN")
    if code in (err.PIN_BLOCKED, err.PIN_AUTH_BLOCKED):
        return FidoPinError(
            "the token has locked its PIN after too many wrong attempts — "
            "unplug and re-insert it, or reset its FIDO application"
        )
    if code is err.PIN_NOT_SET:
        return FidoPinError("this token has no FIDO2 PIN set yet")
    if code is err.PIN_POLICY_VIOLATION:
        return FidoPinError("the token requires a different PIN before it can be used")
    if code in (err.OPERATION_DENIED, err.USER_ACTION_TIMEOUT, err.ACTION_TIMEOUT, err.UP_REQUIRED):
        return FidoTouchError("the token was not touched in time")
    if code in (err.NO_CREDENTIALS, err.INVALID_CREDENTIAL):
        return FidoCredentialError(
            "this token does not hold the credential this key was enrolled with — "
            "it may be a different token"
        )
    return FidoServiceError(f"the token reported an error (CTAP 0x{code:02x})")


class _Interaction(UserInteraction):
    """Feeds the PIN to python-fido2 and reports when a touch is wanted."""

    def __init__(self, pin_text: Callable[[], str], on_touch: Callable[[], None]) -> None:
        self._pin_text = pin_text
        self._on_touch = on_touch

    def prompt_up(self) -> None:
        self._on_touch()

    def request_pin(self, permissions: object, rd_id: object) -> str:
        return self._pin_text()

    def request_uv(self, permissions: object, rd_id: object) -> bool:
        return True


def _pin_reader(pin: SecureBytes) -> Callable[[], str]:
    """Decode the PIN only at the moment the library asks for it.

    The intermediate ``bytes`` is wiped; the resulting ``str`` cannot be, which
    is the limitation this module's docstring records.
    """

    def read() -> str:
        raw = pin.to_bytes()
        try:
            return raw.decode("utf-8")
        finally:
            _zero_bytes_object(raw)

    return read


def _prf_output(extension_results: object) -> bytes | None:
    """Pull ``prf.results.first`` out of whatever shape the library returned."""

    def field(obj: object, name: str) -> object:
        if obj is None:
            return None
        if isinstance(obj, dict):
            return obj.get(name)
        return getattr(obj, name, None)

    results = field(field(extension_results, "prf"), "results")
    value = field(results, "first")
    return value if isinstance(value, bytes) else None


class FidoService:
    """Enrol a FIDO2 token and reproduce the secret it derives."""

    def __init__(self, *, audit: AuditLog | None = None, rp_id: str = RP_ID) -> None:
        self._audit = audit
        self._rp_id = rp_id
        self._origin = f"https://{rp_id}"

    # ------------------------------------------------------------------ presence

    def probe(self) -> tuple[TokenInfo | None, str]:
        """Return the plugged-in token and, when there is none, why not.

        Never raises: the UI polls this, and "no token" is a normal state.
        """
        try:
            device = next(iter(CtapHidDevice.list_devices()), None)
        except OSError:
            return None, _NO_ACCESS
        if device is None:
            return None, _NO_TOKEN
        try:
            info = Ctap2(device).info
        except (CtapError, OSError, ValueError):
            # A device that speaks U2F only cannot answer getInfo at all.
            return None, _NO_PRF
        token = TokenInfo(
            product_name=getattr(device.descriptor, "product_name", "") or "Security key",
            has_pin=bool(info.options.get("clientPin")),
            supports_prf="hmac-secret" in info.extensions,
            supports_resident_keys=bool(info.options.get("rk")),
        )
        return (token, "") if token.is_usable else (token, _NO_PRF)

    def require_token(self) -> TokenInfo:
        token, reason = self.probe()
        if token is None or not token.is_usable:
            raise FidoUnavailableError(reason or _NO_TOKEN)
        return token

    # ------------------------------------------------------------------ enrolment

    def enroll(
        self,
        *,
        pin: SecureBytes,
        user_label: str,
        resident: bool = True,
        on_touch: Callable[[], None] = lambda: None,
    ) -> tuple[FidoCredential, SecureBytes]:
        """Create a credential on the token and derive its secret once.

        Costs **two touches**: CTAP cannot return a ``prf`` output from
        credential creation, so the secret has to be fetched with a follow-up
        assertion. Both are done here so the caller can seal the key's
        passphrase immediately, rather than storing a credential that has never
        been proven to derive anything.

        Returns the binding to persist and the derived secret, which the caller
        owns and must close.
        """
        token = self.require_token()
        if not token.has_pin:
            raise FidoPinError(
                "this token has no FIDO2 PIN set yet — set one on the token first, "
                "then enrol it here"
            )
        if resident and not token.supports_resident_keys:
            raise FidoServiceError("this token cannot store credentials on the device")

        client = self._client(pin, on_touch)
        try:
            registration = client.make_credential(
                PublicKeyCredentialCreationOptions(
                    rp=PublicKeyCredentialRpEntity(id=self._rp_id, name="GPG Meister"),
                    user=PublicKeyCredentialUserEntity(
                        id=secrets.token_bytes(16), name=user_label, display_name=user_label
                    ),
                    challenge=secrets.token_bytes(32),
                    pub_key_cred_params=[
                        PublicKeyCredentialParameters(
                            type=PublicKeyCredentialType.PUBLIC_KEY, alg=alg
                        )
                        for alg in _ALGORITHMS
                    ],
                    authenticator_selection=AuthenticatorSelectionCriteria(
                        resident_key=(
                            ResidentKeyRequirement.REQUIRED
                            if resident
                            else ResidentKeyRequirement.DISCOURAGED
                        ),
                        user_verification=UserVerificationRequirement.REQUIRED,
                    ),
                    extensions={"prf": {}},
                )
            )
        except CtapError as exc:
            self._emit("fido_enrolled", outcome=OUTCOME_FAILED, reason="ctap")
            raise _translate(exc) from exc

        enabled = self._extension_field(registration.client_extension_results, "prf", "enabled")
        if not enabled:
            self._emit("fido_enrolled", outcome=OUTCOME_FAILED, reason="prf_rejected")
            raise FidoServiceError(
                "the token created the credential but refused to enable secret "
                "derivation for it"
            )

        credential = FidoCredential(
            credential_id_b64=_b64(registration.raw_id),
            salt_b64=_b64(secrets.token_bytes(PRF_SALT_LEN)),
            rp_id=self._rp_id,
            resident=resident,
            user_verification=True,
            label=_label_for(token),
        )
        secret = self.derive(credential, pin=pin, on_touch=on_touch)
        self._emit("fido_enrolled", outcome=OUTCOME_OK, resident=str(resident))
        return credential, secret

    # ----------------------------------------------------------------- derivation

    def derive(
        self,
        credential: FidoCredential,
        *,
        pin: SecureBytes,
        on_touch: Callable[[], None] = lambda: None,
    ) -> SecureBytes:
        """Reproduce the token's secret for one binding. Costs one touch."""
        self.require_token()
        client = self._client(pin, on_touch)
        try:
            selection = client.get_assertion(
                PublicKeyCredentialRequestOptions(
                    rp_id=credential.rp_id,
                    challenge=secrets.token_bytes(32),
                    allow_credentials=[
                        PublicKeyCredentialDescriptor(
                            type=PublicKeyCredentialType.PUBLIC_KEY,
                            id=credential.credential_id,
                        )
                    ],
                    user_verification=UserVerificationRequirement.REQUIRED,
                    extensions={"prf": {"eval": {"first": credential.salt}}},
                )
            )
            assertion = selection.get_response(0)
        except CtapError as exc:
            self._emit("fido_derived", outcome=OUTCOME_FAILED, reason="ctap")
            raise _translate(exc) from exc

        raw = _prf_output(assertion.client_extension_results)
        if raw is None or len(raw) != TOKEN_SECRET_LEN:
            self._emit("fido_derived", outcome=OUTCOME_FAILED, reason="no_prf_output")
            raise FidoServiceError("the token returned no usable secret")
        try:
            self._emit("fido_derived", outcome=OUTCOME_OK)
            return SecureBytes.from_bytes(raw)
        finally:
            _zero_bytes_object(raw)

    # ---------------------------------------------------------------- internals

    def _client(self, pin: SecureBytes, on_touch: Callable[[], None]) -> Fido2Client:
        device = next(iter(CtapHidDevice.list_devices()), None)
        if device is None:
            raise FidoUnavailableError(_NO_TOKEN)
        return Fido2Client(
            device,
            client_data_collector=DefaultClientDataCollector(self._origin),
            user_interaction=_Interaction(_pin_reader(pin), on_touch),
        )

    @staticmethod
    def _extension_field(results: object, outer: str, inner: str) -> object:
        def field(obj: object, name: str) -> object:
            if obj is None:
                return None
            if isinstance(obj, dict):
                return obj.get(name)
            return getattr(obj, name, None)

        return field(field(results, outer), inner)

    def _emit(self, event: str, *, outcome: str = OUTCOME_OK, **payload: object) -> None:
        if self._audit is not None:
            self._audit.emit(event, outcome=outcome, **payload)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _label_for(token: TokenInfo) -> str:
    return token.product_name or "Security key"
