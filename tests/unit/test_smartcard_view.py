"""Smartcard panel and the storage column in the key list."""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QLabel

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo, TrustLevel
from gpg_meister.models.smartcard import parse_card_status
from gpg_meister.services.smartcard_service import CardSyncResult
from gpg_meister.ui.keys.key_list_view import _COL_STORAGE, KeyListView
from gpg_meister.ui.keys.key_list_viewmodel import KeyListViewModel
from gpg_meister.ui.keys.smartcard_view import SmartcardDialog

YUBIKEY_AID = "D2760001240103040006123456780000"
PRIMARY_FPR = "1111111111111111111111111111111111111111"
# What a card actually reports for its slots: the *subkey* fingerprints.
CARD_SIG_FPR = "2222222222222222222222222222222222222222"
CARD_ENC_FPR = "3333333333333333333333333333333333333333"
CARD_STATUS = f"""\
Reader:Yubico YubiKey:AID:{YUBIKEY_AID}:openpgp-card:
version:0304:
vendor:0006:Yubico:
serial:12345678:
pinretry:3:0:3:
fpr:{CARD_SIG_FPR}:{CARD_ENC_FPR}::
"""


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _key(*, card_serial: str = "") -> KeyInfo:
    return KeyInfo(
        fingerprint=PRIMARY_FPR,
        user_ids=("Alice <alice@example.org>",),
        algorithm=KeyAlgorithm.EDDSA,
        length=255,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        has_private_key=bool(card_serial),
        is_stub=bool(card_serial),
        card_serial=card_serial,
        subkey_fingerprints=(CARD_SIG_FPR, CARD_ENC_FPR) if card_serial else (),
        trust=TrustLevel.FULL,
    )


class _FakeKeyService:
    def __init__(self, keys: list[KeyInfo] | None = None) -> None:
        self._keys = keys or []

    def list_keys(self) -> list[KeyInfo]:
        return list(self._keys)


class _FakeSmartcardService:
    """Stands in for a plugged-in (or absent) token."""

    def __init__(self, *, card: bool, keys: list[KeyInfo] | None = None) -> None:
        self._card = card
        self._keys = tuple(keys or [])

    def sync(self) -> CardSyncResult:
        if not self._card:
            return CardSyncResult(keys=self._keys)
        info = parse_card_status(CARD_STATUS)
        assert info is not None
        known = {fpr for key in self._keys for fpr in key.all_fingerprints}
        return CardSyncResult(
            card=info,
            linked_fingerprints=tuple(fp for fp in info.key_fingerprints if fp in known),
            missing_fingerprints=tuple(fp for fp in info.key_fingerprints if fp not in known),
            keys=self._keys,
        )


def _pump(app: QApplication, predicate: object, timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if predicate():  # type: ignore[operator]
            return
        time.sleep(0.01)


def test_key_list_shows_the_token_in_the_storage_column() -> None:
    app = _app()
    card_key = _key(card_serial=YUBIKEY_AID)
    view = KeyListView(KeyListViewModel(_FakeKeyService([card_key])))

    _pump(app, lambda: view._table.rowCount() == 1)

    cell = view._table.item(0, _COL_STORAGE)
    assert cell is not None
    assert cell.text() == "YubiKey 12345678"
    assert "PIN" in cell.toolTip()


def test_key_list_marks_a_local_key_as_local() -> None:
    app = _app()
    view = KeyListView(KeyListViewModel(_FakeKeyService([_key()])))

    _pump(app, lambda: view._table.rowCount() == 1)

    cell = view._table.item(0, _COL_STORAGE)
    assert cell is not None
    assert cell.text() == "Public only"


def test_smartcard_button_is_hidden_without_a_smartcard_service() -> None:
    _app()
    view = KeyListView(KeyListViewModel(_FakeKeyService()))

    assert not view._btn_smartcard.isVisible()


def test_card_status_label_follows_the_probe() -> None:
    app = _app()
    vm = KeyListViewModel(
        _FakeKeyService(),
        smartcard_service=_FakeSmartcardService(card=True),  # type: ignore[arg-type]
    )
    view = KeyListView(vm)

    _pump(app, lambda: "YubiKey" in view._card_status.text())

    assert view._card_status.text() == "YubiKey 12345678 connected"


def test_dialog_reports_a_missing_card() -> None:
    app = _app()
    dialog = SmartcardDialog(_FakeSmartcardService(card=False))  # type: ignore[arg-type]

    _pump(app, lambda: dialog._headline.text() == "No smartcard detected")

    assert dialog._headline.text() == "No smartcard detected"


def test_dialog_flags_a_card_key_that_is_missing_its_public_key() -> None:
    app = _app()
    dialog = SmartcardDialog(_FakeSmartcardService(card=True))  # type: ignore[arg-type]

    _pump(app, lambda: "connected" in dialog._headline.text())

    texts = [label.text() for label in dialog.findChildren(QLabel)]
    assert any(text == "YubiKey 12345678 connected" for text in texts)
    assert any("public key missing" in text for text in texts)


def test_dialog_marks_a_linked_card_key_as_usable() -> None:
    app = _app()
    card_key = _key(card_serial=YUBIKEY_AID)
    dialog = SmartcardDialog(
        _FakeSmartcardService(card=True, keys=[card_key]),  # type: ignore[arg-type]
    )

    _pump(app, lambda: "connected" in dialog._headline.text())

    texts = [label.text() for label in dialog.findChildren(QLabel)]
    assert any("usable in GPG Meister" in text for text in texts)
