"""Card admin dialogs: confirmations, validation, and what reaches the service."""

from __future__ import annotations

import os
from datetime import UTC, datetime

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QInputDialog

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo
from gpg_meister.models.smartcard import CardPin, CardSlot, parse_card_status
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.ui.keys.card_admin_view import (
    ChangePinDialog,
    GenerateOnCardDialog,
    MoveKeyToCardDialog,
)

YUBIKEY_AID = "D2760001240103040006123456780000"
KEY_FPR = "A" * 40
SLOT_FPR = "B" * 40

EMPTY_CARD = parse_card_status(
    f"Reader:YubiKey:AID:{YUBIKEY_AID}:openpgp-card:\nserial:12345678:\npinretry:3:0:3:\n"
)
FULL_CARD = parse_card_status(
    f"Reader:YubiKey:AID:{YUBIKEY_AID}:openpgp-card:\nserial:12345678:\n"
    f"pinretry:3:0:3:\nfpr:{SLOT_FPR}:{SLOT_FPR}::\n"
)


class _RecordingService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def change_pin(self, pin: CardPin, *, current: SecureBytes, new: SecureBytes) -> None:
        self.calls.append(("change_pin", {"pin": pin, "new": bytes(new.view())}))

    def unblock_user_pin(self, *, admin_pin: SecureBytes, new_user_pin: SecureBytes) -> None:
        self.calls.append(("unblock", {"new": bytes(new_user_pin.view())}))

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
        self.calls.append(
            (
                "move",
                {
                    "fingerprint": fingerprint,
                    "slot": slot,
                    "key_index": key_index,
                    "allow_overwrite": allow_overwrite,
                },
            )
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
        self.calls.append(
            (
                "generate",
                {
                    "name": name,
                    "email": email,
                    "expiry": expiry,
                    "off_card_backup": off_card_backup,
                    "allow_overwrite": allow_overwrite,
                },
            )
        )


class _FakeKeyService:
    def list_keys(self) -> list[KeyInfo]:
        return [
            KeyInfo(
                fingerprint=KEY_FPR,
                user_ids=("Alice <alice@example.org>",),
                algorithm=KeyAlgorithm.EDDSA,
                length=255,
                created_at=datetime(2026, 1, 1, tzinfo=UTC),
                has_private_key=True,
                subkey_fingerprints=("C" * 40,),
            )
        ]


@pytest.fixture(autouse=True)
def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _drain(app: QApplication) -> None:
    for _ in range(30):
        app.processEvents()


def _answer_confirmations(monkeypatch: pytest.MonkeyPatch, reply: str) -> None:
    monkeypatch.setattr(QInputDialog, "getText", lambda *a, **k: (reply, True))


# ------------------------------------------------------------------- PINs


def test_pin_change_requires_the_repetition_to_match() -> None:
    service = _RecordingService()
    dialog = ChangePinDialog(service, EMPTY_CARD)  # type: ignore[arg-type]
    dialog._current._field.setText("123456")
    dialog._new._field.setText("654321")
    dialog._confirm._field.setText("650000")

    dialog._submit()

    assert service.calls == []
    assert "do not match" in dialog._error_label.text()


def test_pin_change_passes_the_new_pin_verbatim(_app: QApplication) -> None:
    service = _RecordingService()
    dialog = ChangePinDialog(service, EMPTY_CARD)  # type: ignore[arg-type]
    dialog._current._field.setText("123456")
    dialog._new._field.setText("654321")
    dialog._confirm._field.setText("654321")

    dialog._submit()
    _drain(_app)

    assert service.calls[0][0] == "change_pin"
    assert service.calls[0][1]["pin"] is CardPin.USER
    assert service.calls[0][1]["new"] == b"654321"


def test_pin_fields_are_cleared_once_the_work_is_queued() -> None:
    service = _RecordingService()
    dialog = ChangePinDialog(service, EMPTY_CARD)  # type: ignore[arg-type]
    dialog._current._field.setText("123456")
    dialog._new._field.setText("654321")
    dialog._confirm._field.setText("654321")

    dialog._submit()

    assert dialog._current.text() == ""
    assert dialog._new.text() == ""
    assert dialog._confirm.text() == ""


def test_unblock_mode_calls_the_unblock_path(_app: QApplication) -> None:
    service = _RecordingService()
    dialog = ChangePinDialog(service, EMPTY_CARD)  # type: ignore[arg-type]
    dialog._mode.setCurrentText(ChangePinDialog._MODE_UNBLOCK)
    dialog._current._field.setText("12345678")
    dialog._new._field.setText("111111")
    dialog._confirm._field.setText("111111")

    dialog._submit()
    _drain(_app)

    assert service.calls[0][0] == "unblock"


# -------------------------------------------------------------- keytocard


def test_moving_a_key_needs_the_typed_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _RecordingService()
    dialog = MoveKeyToCardDialog(service, _FakeKeyService(), EMPTY_CARD)  # type: ignore[arg-type]
    dialog._on_keys(_FakeKeyService().list_keys())
    dialog._admin_pin._field.setText("12345678")
    _answer_confirmations(monkeypatch, "nope")

    dialog._submit()

    assert service.calls == []


def test_moving_a_key_proceeds_once_confirmed(
    monkeypatch: pytest.MonkeyPatch, _app: QApplication
) -> None:
    service = _RecordingService()
    dialog = MoveKeyToCardDialog(service, _FakeKeyService(), EMPTY_CARD)  # type: ignore[arg-type]
    dialog._on_keys(_FakeKeyService().list_keys())
    dialog._admin_pin._field.setText("12345678")
    dialog._passphrase._field.setText("key pass")
    _answer_confirmations(monkeypatch, "MOVE")

    dialog._submit()
    _drain(_app)

    assert service.calls[0][0] == "move"
    assert service.calls[0][1]["fingerprint"] == KEY_FPR
    assert service.calls[0][1]["allow_overwrite"] is False


def test_moving_onto_an_occupied_slot_needs_the_replace_word(
    monkeypatch: pytest.MonkeyPatch, _app: QApplication
) -> None:
    service = _RecordingService()
    dialog = MoveKeyToCardDialog(service, _FakeKeyService(), FULL_CARD)  # type: ignore[arg-type]
    dialog._on_keys(_FakeKeyService().list_keys())
    dialog._admin_pin._field.setText("12345678")
    # "MOVE" alone is not enough for a slot that already holds a key.
    _answer_confirmations(monkeypatch, "MOVE")

    dialog._submit()
    _drain(_app)

    assert service.calls == []


def test_a_subkey_can_be_selected_for_the_move(
    monkeypatch: pytest.MonkeyPatch, _app: QApplication
) -> None:
    service = _RecordingService()
    dialog = MoveKeyToCardDialog(service, _FakeKeyService(), EMPTY_CARD)  # type: ignore[arg-type]
    dialog._on_keys(_FakeKeyService().list_keys())
    dialog._admin_pin._field.setText("12345678")
    dialog._part_combo.setCurrentIndex(1)  # the first subkey
    _answer_confirmations(monkeypatch, "MOVE")

    dialog._submit()
    _drain(_app)

    assert service.calls[0][1]["key_index"] == 1


def test_the_admin_pin_is_required_for_a_move() -> None:
    service = _RecordingService()
    dialog = MoveKeyToCardDialog(service, _FakeKeyService(), EMPTY_CARD)  # type: ignore[arg-type]
    dialog._on_keys(_FakeKeyService().list_keys())

    dialog._submit()

    assert service.calls == []
    assert "admin PIN" in dialog._error_label.text()


# --------------------------------------------------------------- generate


def test_generating_on_an_empty_card_needs_no_confirmation(_app: QApplication) -> None:
    service = _RecordingService()
    dialog = GenerateOnCardDialog(service, EMPTY_CARD)  # type: ignore[arg-type]
    dialog._name.setText("Alice")
    dialog._email.setText("alice@example.org")
    dialog._admin_pin._field.setText("12345678")
    dialog._user_pin._field.setText("123456")

    dialog._submit()
    _drain(_app)

    assert service.calls[0][0] == "generate"
    assert service.calls[0][1]["allow_overwrite"] is False
    assert service.calls[0][1]["off_card_backup"] is True


def test_generating_over_existing_keys_needs_the_replace_word(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _RecordingService()
    dialog = GenerateOnCardDialog(service, FULL_CARD)  # type: ignore[arg-type]
    dialog._name.setText("Alice")
    dialog._email.setText("alice@example.org")
    dialog._admin_pin._field.setText("12345678")
    dialog._user_pin._field.setText("123456")
    _answer_confirmations(monkeypatch, "yes please")

    dialog._submit()

    assert service.calls == []


def test_generating_over_existing_keys_proceeds_once_confirmed(
    monkeypatch: pytest.MonkeyPatch, _app: QApplication
) -> None:
    service = _RecordingService()
    dialog = GenerateOnCardDialog(service, FULL_CARD)  # type: ignore[arg-type]
    dialog._name.setText("Alice")
    dialog._email.setText("alice@example.org")
    dialog._admin_pin._field.setText("12345678")
    dialog._user_pin._field.setText("123456")
    _answer_confirmations(monkeypatch, "REPLACE")

    dialog._submit()
    _drain(_app)

    assert service.calls[0][1]["allow_overwrite"] is True


def test_generate_requires_an_identity() -> None:
    service = _RecordingService()
    dialog = GenerateOnCardDialog(service, EMPTY_CARD)  # type: ignore[arg-type]
    dialog._admin_pin._field.setText("12345678")
    dialog._user_pin._field.setText("123456")

    dialog._submit()

    assert service.calls == []
    assert "required" in dialog._error_label.text()
