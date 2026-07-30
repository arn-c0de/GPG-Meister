"""The security-key unlock dialog, and where the decrypt tab offers it."""

from __future__ import annotations

import os
from datetime import UTC, datetime

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo, TrustLevel
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.key_unlock_service import UnlockMethods
from gpg_meister.ui.messages.decrypt_view import DecryptView
from gpg_meister.ui.messages.decrypt_viewmodel import DecryptViewModel
from gpg_meister.ui.widgets.token_unlock_dialog import (
    TokenUnlockDialog,
    secure_pin_from,
    token_backed_keys,
)

FPR = "A" * 40
PLAIN_FPR = "B" * 40


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _key(fingerprint: str = FPR) -> KeyInfo:
    return KeyInfo(
        fingerprint=fingerprint,
        user_ids=("Alice <alice@example.org>",),
        algorithm=KeyAlgorithm.EDDSA,
        length=255,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        has_private_key=True,
        trust=TrustLevel.FULL,
    )


class _FakeUnlock:
    """Reports only FPR as enrolled."""

    def __init__(self) -> None:
        self.derived_for: list[str] = []

    def methods_for(self, fingerprint: str) -> UnlockMethods:
        if fingerprint == FPR:
            return UnlockMethods(token_labels=("YubiKey",), has_passphrase=True)
        return UnlockMethods()

    def unlock_with_token(
        self, fingerprint: str, *, pin: SecureBytes, on_touch: object = None
    ) -> SecureBytes:
        self.derived_for.append(fingerprint)
        return SecureBytes.from_bytes(b"the real passphrase")


class _FakeKeyService:
    def __init__(self, keys: list[KeyInfo]) -> None:
        self._keys = keys

    def list_keys(self) -> list[KeyInfo]:
        return list(self._keys)


class _FakeMessageService:
    """Never reached by these tests; the view is what is under test."""

    def decrypt(self, *_: object, **__: object) -> object:  # pragma: no cover
        raise AssertionError("decryption should not run here")


def _decrypt_vm() -> DecryptViewModel:
    return DecryptViewModel(_FakeMessageService())  # type: ignore[arg-type]


# ------------------------------------------------------------------ selection


def test_only_enrolled_keys_are_offered() -> None:
    keys = [_key(FPR), _key(PLAIN_FPR)]

    offered = token_backed_keys(_FakeUnlock(), keys)  # type: ignore[arg-type]

    assert [k.fingerprint for k in offered] == [FPR]


def test_the_dialog_refuses_to_open_with_nothing_to_unlock() -> None:
    """An empty picker would be a dead end the user cannot act on."""
    _app()

    with pytest.raises(ValueError, match="no token-backed key"):
        TokenUnlockDialog(_FakeUnlock(), [])  # type: ignore[arg-type]


def test_a_single_key_hides_the_picker() -> None:
    _app()
    dialog = TokenUnlockDialog(_FakeUnlock(), [_key()])  # type: ignore[arg-type]

    assert not dialog._key_picker.isVisible()
    assert dialog._selected_fingerprint() == FPR


def test_several_keys_can_be_chosen_between() -> None:
    _app()
    keys = [_key(FPR), _key(PLAIN_FPR)]
    dialog = TokenUnlockDialog(_FakeUnlock(), keys)  # type: ignore[arg-type]

    dialog._key_picker.setCurrentIndex(1)

    assert dialog._selected_fingerprint() == PLAIN_FPR


# ---------------------------------------------------------------------- PIN


def test_unlocking_needs_a_pin_first() -> None:
    _app()
    dialog = TokenUnlockDialog(_FakeUnlock(), [_key()])  # type: ignore[arg-type]

    assert not dialog._ok.isEnabled()

    dialog._pin._field.setText("1234")

    assert dialog._ok.isEnabled()


def test_the_pin_is_taken_verbatim() -> None:
    """Normalising it could spend one of the few attempts the token allows."""
    _app()
    dialog = TokenUnlockDialog(_FakeUnlock(), [_key()])  # type: ignore[arg-type]
    # A PIN that Unicode normalisation would alter.
    dialog._pin._field.setText("Ünïcode")

    with secure_pin_from(dialog._pin) as pin:
        assert pin.to_bytes() == "Ünïcode".encode()


def test_an_uncollected_secret_does_not_outlive_the_dialog() -> None:
    _app()
    dialog = TokenUnlockDialog(_FakeUnlock(), [_key()])  # type: ignore[arg-type]
    dialog._secret = SecureBytes.from_bytes(b"passphrase")

    dialog.close()

    assert dialog._secret is None


def test_taking_the_secret_transfers_ownership() -> None:
    _app()
    dialog = TokenUnlockDialog(_FakeUnlock(), [_key()])  # type: ignore[arg-type]
    dialog._secret = SecureBytes.from_bytes(b"passphrase")

    taken = dialog.take_secret()

    assert taken is not None
    assert dialog.take_secret() is None
    with taken:
        assert taken.to_bytes() == b"passphrase"


# ----------------------------------------------------------------- decrypt tab


def test_the_decrypt_tab_hides_the_button_without_an_enrolled_key() -> None:
    _app()
    view = DecryptView(
        _decrypt_vm(),
        unlock=_FakeUnlock(),  # type: ignore[arg-type]
        key_service=_FakeKeyService([_key(PLAIN_FPR)]),  # type: ignore[arg-type]
    )

    view._refresh_token_button()

    assert not view._btn_token.isVisible()


def test_the_decrypt_tab_shows_the_button_once_a_key_is_enrolled() -> None:
    _app()
    view = DecryptView(
        _decrypt_vm(),
        unlock=_FakeUnlock(),  # type: ignore[arg-type]
        key_service=_FakeKeyService([_key(FPR)]),  # type: ignore[arg-type]
    )
    view.show()

    view._refresh_token_button()

    assert view._btn_token.isVisible()
    view.close()


def test_the_button_stays_away_when_no_fido_stack_was_wired() -> None:
    """Older call sites construct DecryptView without the unlock service."""
    _app()
    view = DecryptView(_decrypt_vm())

    view._refresh_token_button()

    assert view._token_backed_keys() == []
    assert not view._btn_token.isVisible()
