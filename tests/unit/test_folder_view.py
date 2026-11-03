from __future__ import annotations

from pathlib import Path
from typing import Any

from pytestqt.qtbot import QtBot

from gpg_meister.ui.messages.folder_view import FolderView
from gpg_meister.ui.messages.folder_viewmodel import FolderViewModel


class _FakeFolders:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def encrypt_folder(self, folder: Path, target: Path, **kwargs: Any) -> Path:
        self.calls.append(("encrypt", {"folder": folder, **kwargs}))
        return target


class _FakeKeys:
    def list_keys(self) -> list[object]:
        return []


def _view(qtbot: QtBot) -> tuple[FolderView, _FakeFolders]:
    folders = _FakeFolders()
    view = FolderView(FolderViewModel(folders, _FakeKeys()))  # type: ignore[arg-type]
    qtbot.addWidget(view)
    view._mode_pass.setChecked(True)
    view._enc_folder.setText("/data/project")
    return view, folders


def test_mismatched_passphrases_are_rejected(qtbot: QtBot) -> None:
    view, folders = _view(qtbot)
    view._enc_passphrase._field.setText("correct horse battery staple")
    view._enc_confirm._field.setText("something else")
    view._submit_encrypt()
    assert "do not match" in view._error_label.text()
    assert folders.calls == []


def test_weak_passphrase_is_rejected(qtbot: QtBot) -> None:
    view, folders = _view(qtbot)
    view._ask_save_path = lambda _folder: "/data/project.tar.gpg"  # type: ignore[method-assign]
    view._enc_passphrase._field.setText("abc")
    view._enc_confirm._field.setText("abc")
    view._submit_encrypt()
    assert "Passphrase rejected" in view._error_label.text()
    assert folders.calls == []


def test_passphrase_mode_encrypts(qtbot: QtBot) -> None:
    view, folders = _view(qtbot)
    view._ask_save_path = lambda _folder: "/data/project.tar.gpg"  # type: ignore[method-assign]
    view._enc_passphrase._field.setText("correct horse battery staple")
    view._enc_confirm._field.setText("correct horse battery staple")
    view._submit_encrypt()
    qtbot.waitUntil(lambda: bool(folders.calls))
    qtbot.waitUntil(lambda: not view._status_label.isHidden())
    _, kwargs = folders.calls[0]
    assert kwargs["folder"] == Path("/data/project")
    assert "passphrase" in kwargs
    assert view._enc_passphrase.text() == ""
