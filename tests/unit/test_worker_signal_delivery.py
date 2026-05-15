from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QDialogButtonBox

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo
from gpg_meister.models.message import DecryptResult, EncryptResult, SignResult, VerifyResult
from gpg_meister.services.vault_service import VaultDescriptor
from gpg_meister.ui.keys.key_create_view import KeyCreateDialog
from gpg_meister.ui.messages.decrypt_viewmodel import DecryptViewModel
from gpg_meister.ui.messages.encrypt_viewmodel import EncryptViewModel
from gpg_meister.ui.messages.sign_viewmodel import SignViewModel
from gpg_meister.ui.messages.verify_viewmodel import VerifyViewModel
from gpg_meister.ui.vault.vault_export_viewmodel import VaultExportViewModel


def _app() -> QApplication:
    return QApplication.instance() or QApplication([])


def _pump_until(predicate: object, timeout: float = 2.0) -> None:
    app = _app()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if callable(predicate) and predicate():
            return
        time.sleep(0.01)
    app.processEvents()


def _key(fingerprint: str = "A" * 40) -> KeyInfo:
    return KeyInfo(
        fingerprint=fingerprint,
        user_ids=("Alice <alice@example.com>",),
        algorithm=KeyAlgorithm.EDDSA,
        length=255,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        has_private_key=True,
    )


class _FakeKeyService:
    def create(self, **_: object) -> KeyInfo:
        return _key()

    def list_keys(self) -> list[KeyInfo]:
        return [_key()]


class _FailingKeyService(_FakeKeyService):
    def create(self, **_: object) -> KeyInfo:
        raise RuntimeError("create failed")


class _FakeMessageService:
    def encrypt(self, *_: object, **__: object) -> EncryptResult:
        return EncryptResult(
            armored_ciphertext="cipher",
            recipient_fingerprints=("A" * 40,),
            signing_fingerprint=None,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

    def decrypt(self, *_: object, **__: object) -> DecryptResult:
        return DecryptResult(
            plaintext=b"hello",
            signer_fingerprint="A" * 40,
            signature_valid=True,
            decrypted_with_fingerprint="A" * 40,
        )

    def sign(self, *_: object, **__: object) -> SignResult:
        return SignResult(
            armored_signature="sig",
            signing_fingerprint="A" * 40,
            detached=True,
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

    def verify(self, *_: object, **__: object) -> VerifyResult:
        return VerifyResult(
            signature_valid=True,
            signer_fingerprint="A" * 40,
            signed_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


class _FakeVaultService:
    def create(self, **_: object) -> VaultDescriptor:
        return VaultDescriptor(path=Path("/tmp/test.vault"), sha256="abc", key_count=1)


def test_key_create_dialog_emits_created_signal() -> None:
    _app()
    dlg = KeyCreateDialog(_FakeKeyService())
    created: list[KeyInfo] = []
    dlg.key_created.connect(created.append)

    dlg._name_field.setText("Alice")
    dlg._email_field.setText("alice@example.com")
    dlg._passphrase_field._field.setText("correct horse battery staple")
    dlg._confirm_field._field.setText("correct horse battery staple")

    ok_button = dlg._buttons.button(QDialogButtonBox.StandardButton.Ok)
    assert ok_button is not None
    assert ok_button.isEnabled()

    dlg._on_submit()

    _pump_until(lambda: len(created) == 1)

    assert len(created) == 1
    assert created[0].fingerprint == "A" * 40
    assert dlg.result() == int(dlg.DialogCode.Accepted)


def test_key_create_dialog_surfaces_background_errors() -> None:
    _app()
    dlg = KeyCreateDialog(_FailingKeyService())

    dlg._name_field.setText("Alice")
    dlg._email_field.setText("alice@example.com")
    dlg._passphrase_field._field.setText("correct horse battery staple")
    dlg._confirm_field._field.setText("correct horse battery staple")
    dlg._on_submit()

    _pump_until(lambda: not dlg._error_label.isHidden())

    assert not dlg._error_label.isHidden()
    assert dlg._error_label.text() == "The operation failed: create failed"


def test_encrypt_viewmodel_emits_result() -> None:
    vm = EncryptViewModel(_FakeMessageService(), _FakeKeyService())
    results: list[EncryptResult] = []
    vm.operation_succeeded.connect(results.append)

    vm.set_plaintext("hello")
    vm.set_recipients(["A" * 40])
    vm.set_trust_confirmed(True)
    vm.submit()

    _pump_until(lambda: len(results) == 1)

    assert len(results) == 1
    assert results[0].armored_ciphertext == "cipher"


def test_decrypt_viewmodel_emits_result() -> None:
    vm = DecryptViewModel(_FakeMessageService())
    results: list[DecryptResult] = []
    vm.operation_succeeded.connect(results.append)

    vm.set_ciphertext("cipher")
    vm.submit(lambda: "correct horse battery staple")

    _pump_until(lambda: len(results) == 1)

    assert len(results) == 1
    assert results[0].plaintext == b"hello"


def test_decrypt_viewmodel_allows_empty_passphrase() -> None:
    vm = DecryptViewModel(_FakeMessageService())
    results: list[DecryptResult] = []
    vm.operation_succeeded.connect(results.append)

    vm.set_ciphertext("cipher")
    assert vm.can_submit() is True
    vm.submit(lambda: "")

    _pump_until(lambda: len(results) == 1)

    assert len(results) == 1
    assert results[0].plaintext == b"hello"


def test_sign_viewmodel_emits_result() -> None:
    vm = SignViewModel(_FakeMessageService(), _FakeKeyService())
    results: list[SignResult] = []
    vm.operation_succeeded.connect(results.append)

    vm.set_data("payload")
    vm.set_fingerprint("A" * 40)
    vm.set_passphrase_non_empty(True)
    vm.submit(lambda: "correct horse battery staple")

    _pump_until(lambda: len(results) == 1)

    assert len(results) == 1
    assert results[0].armored_signature == "sig"


def test_verify_viewmodel_emits_result() -> None:
    vm = VerifyViewModel(_FakeMessageService())
    results: list[VerifyResult] = []
    vm.operation_succeeded.connect(results.append)

    vm.set_data("signed payload")
    vm.set_signature("signature")
    vm.submit()

    _pump_until(lambda: len(results) == 1)

    assert len(results) == 1
    assert results[0].signature_valid is True


def test_vault_export_viewmodel_emits_result() -> None:
    vm = VaultExportViewModel(_FakeVaultService(), _FakeKeyService())
    results: list[VaultDescriptor] = []
    vm.operation_succeeded.connect(results.append)

    fp = "A" * 40
    vm.set_selected([fp])
    vm.set_target_path(Path("/tmp/test.vault"))
    vm.set_master_passphrase("correct horse battery staple")
    vm.set_confirm_passphrase("correct horse battery staple")
    vm.set_key_passphrase(fp, "correct horse battery staple")
    vm.unlock_key(fp)
    vm.submit()

    _pump_until(lambda: len(results) == 1)

    assert len(results) == 1
    assert results[0].sha256 == "abc"
