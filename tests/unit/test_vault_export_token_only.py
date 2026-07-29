"""Token-only vault export: the passphrase may be dropped, but never silently."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo
from gpg_meister.ui.vault.vault_export_view import VaultExportView
from gpg_meister.ui.vault.vault_export_viewmodel import VaultExportViewModel

CARD_FPR = "A" * 40
LOCAL_FPR = "B" * 40
YUBIKEY_AID = "D2760001240103040006123456780000"


def _key(fingerprint: str, *, card_serial: str = "") -> KeyInfo:
    return KeyInfo(
        fingerprint=fingerprint,
        user_ids=("Alice <alice@example.org>",),
        algorithm=KeyAlgorithm.EDDSA,
        length=255,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        has_private_key=True,
        is_stub=bool(card_serial),
        card_serial=card_serial,
    )


class _FakeKeyService:
    def list_keys(self) -> list[KeyInfo]:
        return [_key(LOCAL_FPR), _key(CARD_FPR, card_serial=YUBIKEY_AID)]


class _FakeVaultService:
    pass


def _view() -> VaultExportView:
    QApplication.instance() or QApplication([])
    vm = VaultExportViewModel(_FakeVaultService(), _FakeKeyService())  # type: ignore[arg-type]
    view = VaultExportView(vm)
    # Deliver the key list synchronously instead of waiting on the worker.
    view._on_keys_loaded(_FakeKeyService().list_keys())
    vm._key_map = {key.fingerprint: key for key in _FakeKeyService().list_keys()}
    return view


def _tick_token(view: VaultExportView) -> None:
    from PySide6.QtCore import Qt

    item = view._token_list.item(0)
    assert item is not None
    item.setCheckState(Qt.CheckState.Checked)


def test_only_smartcard_keys_are_offered_as_unlock_keys() -> None:
    view = _view()

    assert view._token_list.count() == 1
    item = view._token_list.item(0)
    assert item is not None
    assert "YubiKey 12345678" in item.text()


def test_token_only_cannot_be_chosen_before_a_token_is() -> None:
    view = _view()

    assert not view._token_only_check.isEnabled()
    assert not view._vm.token_only


def test_ticking_a_token_enables_the_token_only_option() -> None:
    view = _view()

    _tick_token(view)

    assert view._token_only_check.isEnabled()
    assert view._vm.unlock_keys == [CARD_FPR]
    assert not view._vm.token_only  # still opt-in


def test_token_only_warns_and_disables_the_passphrase_fields() -> None:
    view = _view()
    _tick_token(view)

    view._token_only_check.setChecked(True)

    assert view._vm.token_only
    assert view._token_only_warning.isVisibleTo(view)
    assert "gone for good" in view._token_only_warning.text()
    assert not view._pp_box.isEnabled()


def test_unticking_the_last_token_re_arms_the_passphrase() -> None:
    from PySide6.QtCore import Qt

    view = _view()
    _tick_token(view)
    view._token_only_check.setChecked(True)
    assert view._vm.token_only

    item = view._token_list.item(0)
    assert item is not None
    item.setCheckState(Qt.CheckState.Unchecked)

    assert not view._vm.token_only
    assert not view._token_only_check.isChecked()
    assert view._pp_box.isEnabled()


def test_export_needs_no_passphrase_once_token_only_is_confirmed() -> None:
    view = _view()
    vm = view._vm
    _tick_token(view)
    view._token_only_check.setChecked(True)

    vm.set_selected([CARD_FPR])
    vm.set_target_path(Path("/tmp/vault.gpgm"))

    assert vm.can_submit()


def test_export_still_needs_a_matching_passphrase_without_token_only() -> None:
    view = _view()
    vm = view._vm
    _tick_token(view)

    vm.set_selected([CARD_FPR])
    vm.set_target_path(Path("/tmp/vault.gpgm"))
    assert not vm.can_submit()

    vm.set_master_passphrase("a strong vault passphrase")
    vm.set_confirm_passphrase("a strong vault passphrase")
    assert vm.can_submit()
