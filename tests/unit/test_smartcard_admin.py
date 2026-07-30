"""Guards around the destructive card operations, with a stubbed GPG layer."""

from __future__ import annotations

import re

import pytest

from gpg_meister.models.smartcard import CardPin, CardSlot
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.card_scripts import PromptScript
from gpg_meister.services.errors import GPGCardError, GPGCardPinError
from gpg_meister.services.gpg_service import CardStatusOutput, PromptRun
from gpg_meister.services.smartcard_service import SmartcardService

YUBIKEY_AID = "D2760001240103040006123456780000"
KEY_FPR = "A" * 40
SLOT_FPR = "B" * 40

EMPTY_CARD = f"""\
Reader:Yubico YubiKey:AID:{YUBIKEY_AID}:openpgp-card:
serial:12345678:
pinretry:3:0:3:
fpr::::
"""

POPULATED_CARD = f"""\
Reader:Yubico YubiKey:AID:{YUBIKEY_AID}:openpgp-card:
serial:12345678:
pinretry:3:0:3:
fpr:{SLOT_FPR}:{SLOT_FPR}::
"""


class _FakeGPG:
    """Records what would have been run and replays a canned outcome."""

    def __init__(
        self,
        *,
        card_status: str = EMPTY_CARD,
        run: PromptRun | None = None,
        diagnostics: str = "",
        card_error: GPGCardError | None = None,
    ) -> None:
        self._card_status = card_status
        self._diagnostics = diagnostics
        self._card_error = card_error
        self._run = run or PromptRun(returncode=0, stdout=b"", stderr=b"", status=b"")
        self.calls: list[tuple[tuple[str, ...], PromptScript]] = []

    def card_status(self) -> CardStatusOutput:
        if self._card_error is not None:
            raise self._card_error
        return CardStatusOutput(colons=self._card_status, diagnostics=self._diagnostics)

    def list_keys(self, *, secret: bool = False) -> list[object]:
        return []

    def run_prompt_script(self, args: list[str], script: PromptScript) -> PromptRun:
        self.calls.append((tuple(args), script))
        return self._run


def _service(gpg: _FakeGPG) -> SmartcardService:
    return SmartcardService(gpg=gpg)  # type: ignore[arg-type]


def _secret(value: bytes = b"123456") -> SecureBytes:
    return SecureBytes.from_bytes(value)


# --------------------------------------------------------- why no card


def test_a_missing_scdaemon_package_is_named_as_the_reason() -> None:
    """The real-world case: GnuPG installed, `scdaemon` package not.

    gpg exits 0, prints an empty card record, and puts the actual cause on
    stderr — so dropping stderr would leave the user with "no card" and a
    perfectly working, plugged-in token.
    """
    gpg = _FakeGPG(
        card_status="AID:::\n",
        diagnostics=(
            "gpg: error getting version from 'scdaemon': No SmartCard daemon\n"
            "gpg: OpenPGP card not available: No SmartCard daemon\n"
        ),
    )

    card, reason = _service(gpg).probe()

    assert card is None
    assert "scdaemon" in reason
    assert "apt install scdaemon" in reason


def test_the_reason_survives_gpg_exiting_non_zero() -> None:
    """The same missing package, on the path GnuPG actually takes here.

    ``gpg --card-status`` exits 2 for this, so the diagnostics arrive as a
    ``GPGCardError`` whose message has already been normalised to "no smartcard
    is available" — a string none of the reason markers match. Matching on the
    message alone left the most common first-run failure with no explanation at
    all, which is what the fixtures above missed by only ever exiting 0.
    """
    gpg = _FakeGPG(
        card_error=GPGCardError(
            "card status failed: no smartcard is available — insert your token and try again",
            diagnostics=(
                "gpg: error getting version from 'scdaemon': No SmartCard daemon\n"
                "gpg: OpenPGP card not available: No SmartCard daemon\n"
            ),
        ),
    )

    card, reason = _service(gpg).probe()

    assert card is None
    assert "apt install scdaemon" in reason


def test_a_card_error_without_diagnostics_invents_no_reason() -> None:
    gpg = _FakeGPG(card_error=GPGCardError("card status failed: something went wrong"))

    card, reason = _service(gpg).probe()

    assert card is None
    assert reason == ""


def test_a_token_without_a_smartcard_interface_is_explained() -> None:
    gpg = _FakeGPG(
        card_status="",
        diagnostics="gpg: selecting card failed: No such device\n",
    )

    _card, reason = _service(gpg).probe()

    assert "ykman info" in reason


def test_a_card_held_by_another_program_is_explained() -> None:
    gpg = _FakeGPG(card_status="", diagnostics="gpg: selecting card failed\n")

    _card, reason = _service(gpg).probe()

    assert "Another program" in reason


def test_no_reason_is_invented_when_gpg_said_nothing_useful() -> None:
    gpg = _FakeGPG(card_status="", diagnostics="")

    card, reason = _service(gpg).probe()

    assert card is None
    assert reason == ""


def test_the_reason_reaches_the_sync_result() -> None:
    gpg = _FakeGPG(
        card_status="",
        diagnostics="gpg: OpenPGP card not available: No SmartCard daemon\n",
    )

    result = _service(gpg).sync()

    assert result.card is None
    assert "scdaemon" in result.unavailable_reason


def test_a_present_card_reports_no_reason() -> None:
    result = _service(_FakeGPG(card_status=EMPTY_CARD)).sync()

    assert result.card is not None
    assert result.unavailable_reason == ""


# ------------------------------------------------------------ happy paths


def test_changing_a_pin_drives_the_card_editor() -> None:
    gpg = _FakeGPG()

    with _secret(b"123456") as old, _secret(b"654321") as new:
        _service(gpg).change_pin(CardPin.USER, current=old, new=new)

    assert gpg.calls[0][0] == ("--card-edit",)


def test_moving_a_key_targets_the_key_editor() -> None:
    gpg = _FakeGPG()

    with _secret(b"key pass") as pw, _secret(b"12345678") as admin:
        _service(gpg).move_key_to_card(
            KEY_FPR, CardSlot.ENCRYPTION, key_passphrase=pw, admin_pin=admin
        )

    assert gpg.calls[0][0] == ("--edit-key", KEY_FPR)


def test_a_finished_script_leaves_no_secrets_behind() -> None:
    gpg = _FakeGPG()

    with _secret(b"123456") as old, _secret(b"654321") as new:
        _service(gpg).change_pin(CardPin.USER, current=old, new=new)

    _args, script = gpg.calls[0]
    assert script.pending() == {}
    assert script.take("passphrase.enter") is None


# ------------------------------------------------------- destructive guards


def test_moving_onto_an_occupied_slot_is_refused() -> None:
    gpg = _FakeGPG(card_status=POPULATED_CARD)

    with (
        _secret(b"key pass") as pw,
        _secret(b"12345678") as admin,
        pytest.raises(GPGCardError, match="already holds a key"),
    ):
        _service(gpg).move_key_to_card(
            KEY_FPR, CardSlot.SIGNATURE, key_passphrase=pw, admin_pin=admin
        )

    assert gpg.calls == []


def test_moving_onto_an_occupied_slot_proceeds_once_confirmed() -> None:
    gpg = _FakeGPG(card_status=POPULATED_CARD)

    with _secret(b"key pass") as pw, _secret(b"12345678") as admin:
        _service(gpg).move_key_to_card(
            KEY_FPR,
            CardSlot.SIGNATURE,
            key_passphrase=pw,
            admin_pin=admin,
            allow_overwrite=True,
        )

    assert len(gpg.calls) == 1


def test_moving_without_a_card_present_is_refused() -> None:
    gpg = _FakeGPG(card_status="")

    with (
        _secret(b"key pass") as pw,
        _secret(b"12345678") as admin,
        pytest.raises(GPGCardError, match="no smartcard"),
    ):
        _service(gpg).move_key_to_card(
            KEY_FPR, CardSlot.SIGNATURE, key_passphrase=pw, admin_pin=admin
        )

    assert gpg.calls == []


def test_generating_over_existing_card_keys_is_refused() -> None:
    gpg = _FakeGPG(card_status=POPULATED_CARD)

    with (
        _secret(b"12345678") as admin,
        _secret(b"123456") as user,
        pytest.raises(GPGCardError, match="already holds keys"),
    ):
        _service(gpg).generate_key_on_card(
            admin_pin=admin, user_pin=user, name="Alice", email="alice@example.org"
        )

    assert gpg.calls == []


def test_generating_on_an_empty_card_is_allowed() -> None:
    gpg = _FakeGPG(card_status=EMPTY_CARD)

    with _secret(b"12345678") as admin, _secret(b"123456") as user:
        _service(gpg).generate_key_on_card(
            admin_pin=admin, user_pin=user, name="Alice", email="alice@example.org"
        )

    assert len(gpg.calls) == 1


# ------------------------------------------------------------- failures


def test_an_unexpected_prompt_is_reported_as_nothing_changed() -> None:
    gpg = _FakeGPG(
        run=PromptRun(
            returncode=0,
            stdout=b"",
            stderr=b"",
            status=b"",
            unanswered_prompt="cardedit.genkeys.replace_keys",
        )
    )

    with (
        _secret(b"123456") as old,
        _secret(b"654321") as new,
        pytest.raises(GPGCardError, match=re.escape("cardedit.genkeys.replace_keys")),
    ):
        _service(gpg).change_pin(CardPin.USER, current=old, new=new)


def test_a_card_reported_failure_is_surfaced() -> None:
    gpg = _FakeGPG(
        run=PromptRun(
            returncode=0,
            stdout=b"",
            stderr=b"gpg: error changing PIN\n",
            status=b"[GNUPG:] SC_OP_FAILURE 2\n",
        )
    )

    with (
        _secret(b"123456") as old,
        _secret(b"654321") as new,
        pytest.raises(GPGCardError),
    ):
        _service(gpg).change_pin(CardPin.USER, current=old, new=new)


def test_a_rejected_pin_is_reported_as_a_pin_problem() -> None:
    gpg = _FakeGPG(
        run=PromptRun(
            returncode=2,
            stdout=b"",
            stderr=b"gpg: card: Bad PIN\n",
            status=b"",
        )
    )

    with (
        _secret(b"000000") as old,
        _secret(b"654321") as new,
        pytest.raises(GPGCardPinError),
    ):
        _service(gpg).change_pin(CardPin.USER, current=old, new=new)


def test_a_shorter_prompt_sequence_still_counts_as_done() -> None:
    """GnuPG may skip a submenu, leaving scripted answers unused.

    That must not be reported as failure: the card already reported success, and
    telling the user it failed would push them into a retry that burns a PIN
    attempt with a PIN that is no longer current.
    """

    class _ShortRun(_FakeGPG):
        def run_prompt_script(self, args: list[str], script: PromptScript) -> PromptRun:
            script.take("cardedit.prompt")  # only the first menu answer is used
            self.calls.append((tuple(args), script))
            return PromptRun(
                returncode=0, stdout=b"", stderr=b"", status=b"[GNUPG:] SC_OP_SUCCESS\n"
            )

    gpg = _ShortRun()

    with _secret(b"123456") as old, _secret(b"654321") as new:
        _service(gpg).change_pin(CardPin.USER, current=old, new=new)

    assert len(gpg.calls) == 1
