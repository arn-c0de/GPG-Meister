"""Exporting a key whose passphrase only its security key knows.

A key created with a token and no emergency passphrase has a passphrase that
was generated, never shown and sealed under the token. The export tab only ever
offered a text field, so that key — the one most in need of a backup — was the
one key that could not go into a vault.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import QApplication

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.key_unlock_service import UnlockMethods
from gpg_meister.ui.vault.vault_export_view import VaultExportView
from gpg_meister.ui.vault.vault_export_viewmodel import VaultExportViewModel

TOKEN_FPR = "A" * 40
PLAIN_FPR = "B" * 40
CARD_FPR = "C" * 40
YUBIKEY_AID = "D2760001240103040006123456780000"
DERIVED = b"the passphrase the user never saw"


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


_KEYS = [_key(TOKEN_FPR), _key(PLAIN_FPR), _key(CARD_FPR, card_serial=YUBIKEY_AID)]


class _FakeKeyService:
    def list_keys(self) -> list[KeyInfo]:
        return list(_KEYS)


class _FakeUnlock:
    """Only TOKEN_FPR has a security key enrolled."""

    def methods_for(self, fingerprint: str) -> UnlockMethods:
        if fingerprint == TOKEN_FPR:
            return UnlockMethods(token_labels=("YubiKey",))
        return UnlockMethods()


class _RecordingVaultService:
    def __init__(self) -> None:
        self.gpg_passphrases: dict[str, bytes] = {}

    def create(self, *, gpg_passphrases: dict[str, SecureBytes], **_kw: object) -> object:
        # Read the bytes here: the caller closes the buffers on the way out.
        self.gpg_passphrases = {fp: pw.to_bytes() for fp, pw in gpg_passphrases.items()}
        return object()


def _viewmodel(vault: object | None = None) -> VaultExportViewModel:
    QApplication.instance() or QApplication([])
    vm = VaultExportViewModel(
        vault or _RecordingVaultService(),  # type: ignore[arg-type]
        _FakeKeyService(),  # type: ignore[arg-type]
        unlock=_FakeUnlock(),  # type: ignore[arg-type]
    )
    vm._key_map = {key.fingerprint: key for key in _KEYS}
    return vm


def _derived() -> SecureBytes:
    return SecureBytes.from_bytes(DERIVED)


# ------------------------------------------------------------ which keys qualify


def test_only_a_key_with_an_enrolled_token_offers_the_token_route() -> None:
    vm = _viewmodel()

    assert vm.is_token_backed(TOKEN_FPR)
    assert not vm.is_token_backed(PLAIN_FPR)


def test_a_smartcard_key_never_offers_it() -> None:
    """Its private half never leaves the card, so there is nothing to unlock."""
    vm = _viewmodel()

    assert not vm.is_token_backed(CARD_FPR)


def test_without_the_unlock_service_the_route_does_not_exist() -> None:
    QApplication.instance() or QApplication([])
    vm = VaultExportViewModel(
        _RecordingVaultService(),  # type: ignore[arg-type]
        _FakeKeyService(),  # type: ignore[arg-type]
    )
    vm._key_map = {key.fingerprint: key for key in _KEYS}

    assert not vm.is_token_backed(TOKEN_FPR)


# ---------------------------------------------------------------- the handover


def test_a_derived_passphrase_unlocks_the_key_for_export() -> None:
    vm = _viewmodel()
    vm.set_selected([TOKEN_FPR])
    vm.set_target_path(Path("/tmp/vault.gpgm"))
    vm.set_master_passphrase("a strong vault passphrase")
    vm.set_confirm_passphrase("a strong vault passphrase")
    assert not vm.can_submit()

    vm.set_key_secret(TOKEN_FPR, _derived())

    assert vm.is_key_unlocked(TOKEN_FPR)
    assert vm.can_submit()


def test_the_derived_passphrase_reaches_the_vault_verbatim() -> None:
    """Not normalised, not re-encoded: it is the key's passphrase byte for byte."""
    vault = _RecordingVaultService()
    vm = _viewmodel(vault)
    vm.set_selected([TOKEN_FPR])
    vm.set_target_path(Path("/tmp/vault.gpgm"))
    vm.set_master_passphrase("a strong vault passphrase")
    vm.set_confirm_passphrase("a strong vault passphrase")
    vm.set_key_secret(TOKEN_FPR, _derived())

    vm.submit()
    QThreadPool.globalInstance().waitForDone(5000)

    assert vault.gpg_passphrases == {TOKEN_FPR: DERIVED}


def test_abandoning_the_form_wipes_a_derived_passphrase() -> None:
    vm = _viewmodel()
    secret = _derived()
    vm.set_selected([TOKEN_FPR])
    vm.set_key_secret(TOKEN_FPR, secret)

    vm.reset_secrets()

    assert secret.is_closed
    assert not vm.is_key_unlocked(TOKEN_FPR)


def test_deselecting_the_key_wipes_it_too() -> None:
    vm = _viewmodel()
    secret = _derived()
    vm.set_selected([TOKEN_FPR])
    vm.set_key_secret(TOKEN_FPR, secret)

    vm.set_selected([])

    assert secret.is_closed


def test_unlocking_twice_does_not_leak_the_first_buffer() -> None:
    vm = _viewmodel()
    first = _derived()
    vm.set_selected([TOKEN_FPR])
    vm.set_key_secret(TOKEN_FPR, first)

    vm.set_key_secret(TOKEN_FPR, _derived())

    assert first.is_closed


# -------------------------------------------------------------------- the view


def _view() -> VaultExportView:
    vm = _viewmodel()
    view = VaultExportView(vm)
    view._on_keys_loaded(list(_KEYS))
    return view


def _click_key(view: VaultExportView, fingerprint: str) -> None:
    item = view._item_for_fp(fingerprint)
    assert item is not None
    view._on_item_clicked(item)


def test_the_button_appears_only_for_a_token_backed_key() -> None:
    view = _view()

    _click_key(view, PLAIN_FPR)
    assert not view._btn_token_unlock.isVisibleTo(view)

    _click_key(view, TOKEN_FPR)
    assert view._btn_token_unlock.isVisibleTo(view)


def test_the_passphrase_field_stays_open_for_an_enrolled_key() -> None:
    """It may still have an emergency passphrase, and typing it is faster."""
    view = _view()

    _click_key(view, TOKEN_FPR)

    assert view._unlock_pp.isEnabled()
    assert "security key" in view._unlock_label.text()
