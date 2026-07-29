"""The vault import wizard's choice between a master passphrase and a card PIN."""

from __future__ import annotations

import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gpg_meister.services.vault_service import VaultUnlockInfo, VaultUnlockSlot
from gpg_meister.ui.vault.vault_import_view import _PassphrasePage

FPR = "A" * 40


class _FakeVaultService:
    def __init__(self, info: VaultUnlockInfo | Exception) -> None:
        self._info = info

    def unlock_info(self, source_path: Path) -> VaultUnlockInfo:
        if isinstance(self._info, Exception):
            raise self._info
        return self._info


def _page(info: VaultUnlockInfo | Exception) -> _PassphrasePage:
    QApplication.instance() or QApplication([])
    page = _PassphrasePage(_FakeVaultService(info))  # type: ignore[arg-type]
    # Wizard fields only resolve once a page belongs to a QWizard; stand in for
    # the file the previous page would have selected.
    page.field = lambda _name: "/nonexistent/vault.gpgm"  # type: ignore[method-assign]
    page._show_unlock_methods()
    return page


def _slot_info(*, accepts_passphrase: bool = True) -> VaultUnlockInfo:
    return VaultUnlockInfo(
        version=3,
        accepts_passphrase=accepts_passphrase,
        smartcard_slots=(VaultUnlockSlot(fingerprint=FPR, label="YubiKey 12345678"),),
    )


def test_passphrase_only_vault_offers_no_choice() -> None:
    page = _page(VaultUnlockInfo(version=2, accepts_passphrase=True))

    assert not page.uses_smartcard()
    assert not page._mode_box.isVisibleTo(page)
    assert page._pp_label.text() == "Master passphrase:"


def test_token_vault_offers_the_card_and_names_it() -> None:
    page = _page(_slot_info())

    assert page._mode_box.isVisibleTo(page)
    assert "YubiKey 12345678" in page._mode_hint.text()
    assert not page.uses_smartcard()  # the passphrase stays the default


def test_choosing_the_card_switches_the_credential_prompt() -> None:
    page = _page(_slot_info())

    page._mode_card.setChecked(True)

    assert page.uses_smartcard()
    assert page._pp_label.text() == "Smartcard PIN:"


def test_card_mode_survives_leaving_the_page() -> None:
    """The result page reads the mode after the wizard advanced past this page."""
    page = _page(_slot_info())
    page._mode_card.setChecked(True)

    page.hide()
    page._mode_box.hide()

    assert page.uses_smartcard()


def test_unreadable_header_falls_back_to_the_passphrase_prompt() -> None:
    page = _page(OSError("no such file"))

    assert not page.uses_smartcard()
    assert not page._mode_box.isVisibleTo(page)


def test_reinitialising_for_another_vault_clears_the_offer() -> None:
    page = _page(_slot_info())
    page._mode_card.setChecked(True)
    assert page.uses_smartcard()

    page._vault_svc = _FakeVaultService(VaultUnlockInfo(version=2, accepts_passphrase=True))  # type: ignore[assignment]
    page._show_unlock_methods()

    assert not page.uses_smartcard()
