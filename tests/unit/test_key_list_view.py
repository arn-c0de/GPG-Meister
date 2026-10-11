from __future__ import annotations

import os
import time
from datetime import UTC, datetime

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QApplication, QInputDialog, QMessageBox

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo, TrustLevel
from gpg_meister.ui.keys.key_list_view import KeyListView
from gpg_meister.ui.keys.key_list_viewmodel import KeyListViewModel

VALID_FP = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"


class _FakeKeyService:
    def list_keys(self) -> list[object]:
        return []


def _key(*, has_private_key: bool) -> KeyInfo:
    return KeyInfo(
        fingerprint=VALID_FP,
        user_ids=("Alice <alice@example.org>",),
        algorithm=KeyAlgorithm.EDDSA,
        length=255,
        created_at=datetime.now(UTC),
        has_private_key=has_private_key,
        trust=TrustLevel.FULL,
    )


def test_new_key_button_reenabled_after_initial_refresh() -> None:
    app = QApplication.instance() or QApplication([])
    view = KeyListView(KeyListViewModel(_FakeKeyService()))

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        app.processEvents()
        if view._btn_create.isEnabled():
            break
        time.sleep(0.01)

    assert view._btn_create.isEnabled()


def test_delete_public_key_requires_text_confirmation(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    view = KeyListView(KeyListViewModel(_FakeKeyService()))
    key = _key(has_private_key=False)
    deleted: list[tuple[str, bool]] = []

    monkeypatch.setattr(view, "_selected_key", lambda: key)
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        lambda *args, **kwargs: ("nope", True),
    )
    monkeypatch.setattr(
        view._vm,
        "request_delete",
        lambda fingerprint, *, including_secret, passphrase=None: deleted.append(
            (fingerprint, including_secret)
        ),
    )

    view._delete_selected()
    app.processEvents()

    assert deleted == []


def test_delete_public_key_proceeds_after_text_confirmation(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    view = KeyListView(KeyListViewModel(_FakeKeyService()))
    key = _key(has_private_key=False)
    deleted: list[tuple[str, bool]] = []

    monkeypatch.setattr(view, "_selected_key", lambda: key)
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        lambda *args, **kwargs: ("DELETE", True),
    )
    monkeypatch.setattr(
        view._vm,
        "request_delete",
        lambda fingerprint, *, including_secret, passphrase=None: deleted.append(
            (fingerprint, including_secret)
        ),
    )

    view._delete_selected()
    app.processEvents()

    assert deleted == [(key.fingerprint, False)]


def test_delete_public_key_shows_simple_confirmation_when_text_disabled(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    view = KeyListView(
        KeyListViewModel(_FakeKeyService(), require_delete_text_confirmation=False)
    )
    key = _key(has_private_key=False)
    deleted: list[tuple[str, bool]] = []

    monkeypatch.setattr(view, "_selected_key", lambda: key)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(
        view._vm,
        "request_delete",
        lambda fingerprint, *, including_secret, passphrase=None: deleted.append(
            (fingerprint, including_secret)
        ),
    )

    view._delete_selected()
    app.processEvents()

    assert deleted == [(key.fingerprint, False)]


def test_delete_private_key_requires_text_confirmation(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    view = KeyListView(KeyListViewModel(_FakeKeyService()))
    key = _key(has_private_key=True)
    deleted: list[tuple[str, bool]] = []

    monkeypatch.setattr(view, "_selected_key", lambda: key)
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        lambda *args, **kwargs: ("nope", True),
    )
    monkeypatch.setattr(
        view._vm,
        "request_delete",
        lambda fingerprint, *, including_secret, passphrase=None: deleted.append(
            (fingerprint, including_secret)
        ),
    )

    view._delete_selected()
    app.processEvents()

    assert deleted == []


def test_delete_private_key_proceeds_after_text_confirmation(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    view = KeyListView(KeyListViewModel(_FakeKeyService()))
    key = _key(has_private_key=True)
    deleted: list[tuple[str, bool]] = []

    monkeypatch.setattr(view, "_selected_key", lambda: key)
    monkeypatch.setattr(
        QInputDialog,
        "getText",
        lambda *args, **kwargs: ("DELETE", True),
    )
    monkeypatch.setattr(
        view._vm,
        "request_delete",
        lambda fingerprint, *, including_secret, passphrase=None: deleted.append(
            (fingerprint, including_secret)
        ),
    )

    view._delete_selected()
    app.processEvents()

    assert deleted == [(key.fingerprint, True)]


def test_delete_private_key_shows_simple_confirmation_when_text_disabled(monkeypatch) -> None:
    app = QApplication.instance() or QApplication([])
    view = KeyListView(
        KeyListViewModel(_FakeKeyService(), require_delete_text_confirmation=False)
    )
    key = _key(has_private_key=True)
    deleted: list[tuple[str, bool]] = []

    monkeypatch.setattr(view, "_selected_key", lambda: key)
    monkeypatch.setattr(
        QMessageBox,
        "question",
        lambda *args, **kwargs: QMessageBox.StandardButton.Yes,
    )
    monkeypatch.setattr(
        view._vm,
        "request_delete",
        lambda fingerprint, *, including_secret, passphrase=None: deleted.append(
            (fingerprint, including_secret)
        ),
    )

    view._delete_selected()
    app.processEvents()

    assert deleted == [(key.fingerprint, True)]


def test_storage_location_points_at_secret_key_folder(tmp_path) -> None:
    (tmp_path / "private-keys-v1.d").mkdir()
    vm = KeyListViewModel(_FakeKeyService(), keyring_dir=tmp_path)

    assert vm.storage_location(_key(has_private_key=True)) == tmp_path / "private-keys-v1.d"
    assert vm.storage_location(_key(has_private_key=False)) == tmp_path


def test_storage_location_none_for_smartcard_key_or_unknown_keyring(tmp_path) -> None:
    card_key = _key(has_private_key=True).model_copy(
        update={"card_serial": "D2760001240100000006123456780000"}
    )

    assert (
        KeyListViewModel(_FakeKeyService(), keyring_dir=tmp_path).storage_location(card_key) is None
    )
    assert KeyListViewModel(_FakeKeyService()).storage_location(_key(has_private_key=True)) is None


def test_open_location_warns_when_no_file_manager(monkeypatch, tmp_path) -> None:
    QApplication.instance() or QApplication([])
    view = KeyListView(KeyListViewModel(_FakeKeyService(), keyring_dir=tmp_path))
    warnings: list[str] = []

    monkeypatch.setattr(QDesktopServices, "openUrl", lambda _url: False)
    monkeypatch.setattr(QMessageBox, "warning", lambda _parent, _title, text: warnings.append(text))

    view._open_location(tmp_path)

    assert warnings and str(tmp_path) in warnings[0]
