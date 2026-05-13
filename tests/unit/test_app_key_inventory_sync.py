from __future__ import annotations

from gpg_meister.app import _wire_key_inventory_updates


class _FakeSignal:
    def __init__(self) -> None:
        self._callbacks: list[object] = []

    def connect(self, callback: object) -> None:
        self._callbacks.append(callback)

    def emit(self, value: object) -> None:
        for callback in self._callbacks:
            if callable(callback):
                callback(value)


class _FakeKeyListViewModel:
    def __init__(self) -> None:
        self.keys_changed = _FakeSignal()


class _FakeLoader:
    def __init__(self) -> None:
        self.calls = 0

    def load_keys(self) -> None:
        self.calls += 1


def test_key_inventory_updates_refresh_dependent_viewmodels() -> None:
    key_vm = _FakeKeyListViewModel()
    encrypt_vm = _FakeLoader()
    sign_vm = _FakeLoader()
    export_vm = _FakeLoader()

    _wire_key_inventory_updates(key_vm, encrypt_vm, sign_vm, export_vm)
    key_vm.keys_changed.emit(["dummy"])

    assert encrypt_vm.calls == 1
    assert sign_vm.calls == 1
    assert export_vm.calls == 1


def test_key_inventory_updates_tolerate_missing_export_vm() -> None:
    key_vm = _FakeKeyListViewModel()
    encrypt_vm = _FakeLoader()
    sign_vm = _FakeLoader()

    _wire_key_inventory_updates(key_vm, encrypt_vm, sign_vm, export_vm=None)
    key_vm.keys_changed.emit(["dummy"])

    assert encrypt_vm.calls == 1
    assert sign_vm.calls == 1
