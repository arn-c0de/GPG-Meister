"""Answer scripts for GnuPG's interactive card editors."""

from __future__ import annotations

import pytest

from gpg_meister.models.smartcard import CardPin, CardSlot
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.card_scripts import (
    PROMPT_BACKUP_ENC,
    PROMPT_CARD_MENU,
    PROMPT_KEY_MENU,
    PROMPT_PIN_MENU,
    PROMPT_REPLACE_KEYS,
    PROMPT_SLOT,
    SECRET_PROMPTS,
    PromptScript,
    card_operation_failed,
    card_operation_succeeded,
    change_pin_script,
    generate_on_card_script,
    keytocard_script,
    unblock_pin_script,
)


def _drain(script: PromptScript, keyword: str) -> list[str]:
    answers: list[str] = []
    while (answer := script.take(keyword)) is not None:
        answers.append(answer.decode())
    return answers


# ---------------------------------------------------------------- queueing


def test_answers_are_consumed_in_order() -> None:
    script = PromptScript()
    script.add("prompt", "first", "second")

    assert script.take("prompt") == b"first"
    assert script.take("prompt") == b"second"
    assert script.take("prompt") is None


def test_unknown_prompt_has_no_answer() -> None:
    script = PromptScript()
    script.add("known", "yes")

    assert script.take("something.else") is None


def test_aliased_prompts_share_one_queue() -> None:
    """Only one of GnuPG's secret-prompt keywords is used per version, and
    whichever it is must consume the same ordered answers."""
    script = PromptScript()
    script.share(("a.ask", "b.ask"), "one", "two")

    assert script.take("a.ask") == b"one"
    assert script.take("b.ask") == b"two"
    assert script.take("a.ask") is None


def test_pending_reports_answers_that_were_never_used() -> None:
    script = PromptScript()
    script.add("prompt", "a", "b")
    script.take("prompt")

    assert script.pending() == {"prompt": 1}


def test_wipe_clears_consumed_and_queued_answers() -> None:
    script = PromptScript()
    script.add("prompt", "secret-value")

    script.wipe()

    assert script.take("prompt") is None
    assert script.pending() == {}


# ------------------------------------------------------------ PIN changes


def test_user_pin_change_picks_the_first_submenu_entry() -> None:
    with SecureBytes.from_bytes(b"123456") as old, SecureBytes.from_bytes(b"654321") as new:
        script = change_pin_script(CardPin.USER, current=old, new=new)

    assert _drain(script, PROMPT_CARD_MENU) == ["admin", "passwd", "quit"]
    assert _drain(script, PROMPT_PIN_MENU) == ["1", "Q"]
    # Current PIN, then the new one twice for GnuPG's confirmation prompt.
    assert _drain(script, SECRET_PROMPTS[0]) == ["123456", "654321", "654321"]


def test_admin_pin_change_picks_the_third_submenu_entry() -> None:
    with SecureBytes.from_bytes(b"12345678") as old, SecureBytes.from_bytes(b"87654321") as new:
        script = change_pin_script(CardPin.ADMIN, current=old, new=new)

    assert _drain(script, PROMPT_PIN_MENU) == ["3", "Q"]


def test_unblock_uses_the_admin_pin_and_the_unblock_entry() -> None:
    with SecureBytes.from_bytes(b"12345678") as admin, SecureBytes.from_bytes(b"111111") as new:
        script = unblock_pin_script(admin_pin=admin, new_user_pin=new)

    assert _drain(script, PROMPT_PIN_MENU) == ["2", "Q"]
    assert _drain(script, SECRET_PROMPTS[0]) == ["12345678", "111111", "111111"]


@pytest.mark.parametrize("bad", [b"12\n34", b"12\r34", b"12\x0034", b""])
def test_a_pin_with_framing_bytes_is_rejected(bad: bytes) -> None:
    """A newline would end the line early and desynchronise every later answer."""
    with (
        SecureBytes.from_bytes(bad) as broken,
        SecureBytes.from_bytes(b"654321") as new,
        pytest.raises(ValueError),
    ):
        change_pin_script(CardPin.USER, current=broken, new=new)


# -------------------------------------------------------------- keytocard


def test_moving_a_subkey_selects_it_first() -> None:
    with SecureBytes.from_bytes(b"key pass") as pw, SecureBytes.from_bytes(b"12345678") as admin:
        script = keytocard_script(
            CardSlot.ENCRYPTION, key_index=2, key_passphrase=pw, admin_pin=admin
        )

    assert _drain(script, PROMPT_KEY_MENU) == ["key 2", "keytocard", "save"]
    assert _drain(script, PROMPT_SLOT) == ["2"]


def test_moving_the_primary_key_needs_no_selection() -> None:
    with SecureBytes.from_bytes(b"key pass") as pw, SecureBytes.from_bytes(b"12345678") as admin:
        script = keytocard_script(
            CardSlot.SIGNATURE, key_index=0, key_passphrase=pw, admin_pin=admin
        )

    assert _drain(script, PROMPT_KEY_MENU) == ["keytocard", "save"]
    assert _drain(script, PROMPT_SLOT) == ["1"]


# --------------------------------------------------------------- generate


def test_generate_refuses_to_replace_keys_unless_asked_to() -> None:
    with SecureBytes.from_bytes(b"12345678") as admin, SecureBytes.from_bytes(b"123456") as user:
        script = generate_on_card_script(
            admin_pin=admin,
            user_pin=user,
            name="Alice",
            email="alice@example.org",
            expiry="0",
            off_card_backup=True,
            replace_existing=False,
        )

    assert _drain(script, PROMPT_REPLACE_KEYS) == ["n"]
    assert _drain(script, PROMPT_BACKUP_ENC) == ["y"]


def test_generate_replaces_keys_only_on_an_explicit_decision() -> None:
    with SecureBytes.from_bytes(b"12345678") as admin, SecureBytes.from_bytes(b"123456") as user:
        script = generate_on_card_script(
            admin_pin=admin,
            user_pin=user,
            name="Alice",
            email="alice@example.org",
            expiry="1y",
            off_card_backup=False,
            replace_existing=True,
        )

    assert _drain(script, PROMPT_REPLACE_KEYS) == ["y"]
    assert _drain(script, PROMPT_BACKUP_ENC) == ["n"]


# ---------------------------------------------------------------- outcome


def test_card_failure_is_read_from_the_status_records() -> None:
    """GnuPG exits 0 for several card errors, so the records decide."""
    records = [["SC_OP_FAILURE", "2"], ["CARDCTRL", "3"]]

    assert card_operation_failed(records) == "2"
    assert not card_operation_succeeded(records)


def test_card_success_is_recognised() -> None:
    records = [["CARDCTRL", "3"], ["SC_OP_SUCCESS"]]

    assert card_operation_failed(records) is None
    assert card_operation_succeeded(records)
