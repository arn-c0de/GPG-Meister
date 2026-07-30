"""Creating a key whose passphrase lives on a security key: form rules and UI."""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from gpg_meister.ui.keys.key_create_view import KeyCreateDialog
from gpg_meister.ui.keys.key_create_viewmodel import KeyCreateViewModel

STRONG = "correct-horse-battery-staple-42"


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


class _FakeKeyService:
    def __init__(self, *, supports_token: bool = True) -> None:
        self.supports_token_unlock = supports_token
        self.token_calls: list[dict[str, object]] = []

    def create_with_token(self, **kwargs: object) -> object:
        self.token_calls.append(kwargs)
        raise RuntimeError("not run in these tests")


def _vm(**kwargs: object) -> KeyCreateViewModel:
    _app()
    vm = KeyCreateViewModel(_FakeKeyService(**kwargs))  # type: ignore[arg-type]
    vm.set_name("Alice")
    vm.set_email("alice@example.org")
    return vm


# ------------------------------------------------------------------ form rules


def test_without_a_token_a_passphrase_is_still_required() -> None:
    vm = _vm()

    assert not vm._is_valid()

    vm.set_passphrase(STRONG)
    vm.set_confirm(STRONG)

    assert vm._is_valid()


def test_token_mode_requires_the_pin() -> None:
    vm = _vm()
    vm.set_use_token(True)
    vm.set_passphrase(STRONG)
    vm.set_confirm(STRONG)

    assert not vm._is_valid()

    vm.set_pin("1234")

    assert vm._is_valid()


def test_a_token_only_key_needs_no_passphrase() -> None:
    vm = _vm()
    vm.set_use_token(True)
    vm.set_pin("1234")
    vm.set_token_only(True)

    assert vm._is_valid()


def test_the_emergency_passphrase_is_held_to_the_usual_standard() -> None:
    """It protects the same key, so a weak one is no more acceptable here."""
    vm = _vm()
    vm.set_use_token(True)
    vm.set_pin("1234")
    vm.set_passphrase("short")
    vm.set_confirm("short")

    assert not vm._is_valid()


def test_leaving_token_mode_re_arms_the_passphrase_requirement() -> None:
    """Otherwise a form left token-only would submit a key nothing can open."""
    vm = _vm()
    vm.set_use_token(True)
    vm.set_pin("1234")
    vm.set_token_only(True)
    assert vm._is_valid()

    vm.set_use_token(False)

    assert not vm.token_only
    assert not vm._is_valid()


def test_token_only_cannot_be_set_outside_token_mode() -> None:
    vm = _vm()
    vm.set_token_only(True)

    assert not vm.token_only


def test_the_option_is_hidden_when_no_fido_stack_exists() -> None:
    assert not _vm(supports_token=False).supports_token


# ------------------------------------------------------------------------- UI


def test_the_dialog_hides_the_token_option_when_unsupported() -> None:
    _app()
    dialog = KeyCreateDialog(_FakeKeyService(supports_token=False))  # type: ignore[arg-type]

    assert not dialog._use_token.isVisible()


def test_ticking_the_option_reveals_the_pin_field() -> None:
    _app()
    dialog = KeyCreateDialog(_FakeKeyService())  # type: ignore[arg-type]
    dialog.show()

    dialog._use_token.setChecked(True)

    assert dialog._pin_field.isVisible()
    assert dialog._token_only.isVisible()
    assert dialog._passphrase_label.text() == "Emergency passphrase:"
    dialog.close()


def test_token_only_hides_the_passphrase_fields_and_warns() -> None:
    _app()
    dialog = KeyCreateDialog(_FakeKeyService())  # type: ignore[arg-type]
    dialog.show()
    dialog._use_token.setChecked(True)

    dialog._token_only.setChecked(True)

    assert not dialog._passphrase_field.isVisible()
    assert dialog._token_only_warning.isVisible()
    assert "gone for good" in dialog._token_only_warning.text()
    dialog.close()


def test_un_ticking_the_option_restores_the_passphrase_fields() -> None:
    _app()
    dialog = KeyCreateDialog(_FakeKeyService())  # type: ignore[arg-type]
    dialog.show()
    dialog._use_token.setChecked(True)
    dialog._token_only.setChecked(True)

    dialog._use_token.setChecked(False)

    assert dialog._passphrase_field.isVisible()
    assert not dialog._token_only.isChecked()
    assert dialog._passphrase_label.text() == "Passphrase:"
    dialog.close()


def test_a_typed_passphrase_is_dropped_when_switching_to_token_only() -> None:
    """It would otherwise sit in a hidden widget and be silently ignored."""
    _app()
    dialog = KeyCreateDialog(_FakeKeyService())  # type: ignore[arg-type]
    dialog.show()
    dialog._passphrase_field._field.setText(STRONG)
    dialog._use_token.setChecked(True)

    dialog._token_only.setChecked(True)

    assert dialog._passphrase_field.text() == ""
    dialog.close()
