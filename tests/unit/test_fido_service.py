"""Token presence and CTAP error translation, with the hardware stubbed out."""

from __future__ import annotations

import pytest
from fido2.ctap import CtapError

from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services import fido_service
from gpg_meister.services.fido_service import (
    FidoCredentialError,
    FidoPinError,
    FidoService,
    FidoServiceError,
    FidoTouchError,
    FidoUnavailableError,
    TokenInfo,
    _pin_reader,
    _prf_output,
    _translate,
)


class _FakeInfo:
    def __init__(self, *, prf: bool = True, pin: bool = False, rk: bool = True) -> None:
        self.extensions = ["hmac-secret"] if prf else ["credProtect"]
        self.options = {"clientPin": pin, "rk": rk}


class _FakeDescriptor:
    product_name = "Yubico YubiKey FIDO"


class _FakeDevice:
    descriptor = _FakeDescriptor()


def _install_device(monkeypatch: pytest.MonkeyPatch, device: object, info: object) -> None:
    monkeypatch.setattr(
        fido_service.CtapHidDevice, "list_devices", staticmethod(lambda: iter([device]))
    )
    monkeypatch.setattr(fido_service, "Ctap2", lambda _dev: type("C", (), {"info": info})())


# ------------------------------------------------------------------- presence


def test_no_device_is_reported_as_a_missing_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fido_service.CtapHidDevice, "list_devices", staticmethod(lambda: iter([]))
    )

    token, reason = FidoService().probe()

    assert token is None
    assert "Plug your token" in reason


def test_an_unreadable_device_node_names_the_udev_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Linux first-run failure: the token is there, hidraw is not readable.

    Without this the symptom is identical to having no token at all, and the
    user would go looking for the wrong problem.
    """

    def _boom() -> object:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(fido_service.CtapHidDevice, "list_devices", staticmethod(_boom))

    token, reason = FidoService().probe()

    assert token is None
    assert "udev" in reason


def test_a_usable_token_is_described(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_device(monkeypatch, _FakeDevice(), _FakeInfo(prf=True, pin=True))

    token, reason = FidoService().probe()

    assert token is not None
    assert token.product_name == "Yubico YubiKey FIDO"
    assert token.has_pin
    assert token.supports_prf
    assert token.is_usable
    assert reason == ""


def test_a_token_without_hmac_secret_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_device(monkeypatch, _FakeDevice(), _FakeInfo(prf=False))

    token, reason = FidoService().probe()

    assert token is not None
    assert not token.is_usable
    assert "hmac-secret" in reason


def test_require_token_raises_when_unusable(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_device(monkeypatch, _FakeDevice(), _FakeInfo(prf=False))

    with pytest.raises(FidoUnavailableError):
        FidoService().require_token()


def test_enrolment_refuses_a_token_without_a_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    """PIN + touch was the chosen policy, so a PIN-less token cannot enrol."""
    _install_device(monkeypatch, _FakeDevice(), _FakeInfo(prf=True, pin=False))

    with SecureBytes.from_bytes(b"1234") as pin, pytest.raises(FidoPinError, match="no FIDO2 PIN"):
        FidoService().enroll(pin=pin, user_label="test")


# ---------------------------------------------------------- error translation


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (CtapError.ERR.PIN_INVALID, FidoPinError),
        (CtapError.ERR.PIN_AUTH_INVALID, FidoPinError),
        (CtapError.ERR.PIN_BLOCKED, FidoPinError),
        (CtapError.ERR.PIN_NOT_SET, FidoPinError),
        (CtapError.ERR.USER_ACTION_TIMEOUT, FidoTouchError),
        (CtapError.ERR.UP_REQUIRED, FidoTouchError),
        (CtapError.ERR.NO_CREDENTIALS, FidoCredentialError),
        (CtapError.ERR.INVALID_CREDENTIAL, FidoCredentialError),
        (CtapError.ERR.INVALID_LENGTH, FidoServiceError),
    ],
)
def test_ctap_errors_map_to_actionable_types(code: int, expected: type[Exception]) -> None:
    assert isinstance(_translate(CtapError(code)), expected)


def test_a_missed_touch_is_not_reported_as_a_hardware_fault() -> None:
    """YubiKeys answer "you never touched me" with OPERATION_DENIED.

    Verified against the physical token: the call returns 0x27 after ~29s, the
    user-presence window. Reporting that as a generic device error would send
    the user chasing a fault that does not exist.
    """
    translated = _translate(CtapError(CtapError.ERR.OPERATION_DENIED))

    assert isinstance(translated, FidoTouchError)
    assert "not touched" in str(translated)


def test_a_blocked_pin_says_what_to_do() -> None:
    assert "reset" in str(_translate(CtapError(CtapError.ERR.PIN_AUTH_BLOCKED)))


# ------------------------------------------------------------------ plumbing


def test_the_pin_is_decoded_only_when_asked_for() -> None:
    with SecureBytes.from_bytes(b"123456") as pin:
        read = _pin_reader(pin)

        assert read() == "123456"
        assert read() == "123456"


@pytest.mark.parametrize(
    "results",
    [
        {"prf": {"results": {"first": b"\x01" * 32}}},
        {"prf": type("O", (), {"results": type("R", (), {"first": b"\x01" * 32})()})()},
    ],
)
def test_the_prf_output_is_read_from_either_library_shape(results: object) -> None:
    """python-fido2 returns dataclasses here, older builds returned dicts."""
    assert _prf_output(results) == b"\x01" * 32


@pytest.mark.parametrize(
    "results",
    [None, {}, {"prf": None}, {"prf": {"results": None}}, {"prf": {"results": {"first": None}}}],
)
def test_a_missing_prf_output_is_reported_as_absent(results: object) -> None:
    assert _prf_output(results) is None


def test_token_info_usability_hangs_on_prf() -> None:
    assert TokenInfo("k", has_pin=True, supports_prf=True, supports_resident_keys=True).is_usable
    assert not TokenInfo(
        "k", has_pin=True, supports_prf=False, supports_resident_keys=True
    ).is_usable
