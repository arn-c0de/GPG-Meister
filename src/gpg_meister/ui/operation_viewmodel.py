"""Shared base for the message-tab viewmodels (encrypt / decrypt / sign / verify).

Every one of those viewmodels ran the same background-operation lifecycle: the
three signals below, a global ``QThreadPool``, and identical
``_on_error`` / ``_on_finished`` / result-dispatch handlers wired onto a
:class:`~gpg_meister.ui.worker.Worker`. That boilerplate lives here once;
subclasses keep only their state and their ``_do`` closure.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QThreadPool, Signal

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.security.password_policy import normalise_passphrase
from gpg_meister.security.secure_bytes import SecureBytes, secure_from_text
from gpg_meister.services.key_service import KeyService
from gpg_meister.ui.worker import Worker


def read_passphrase(get_passphrase: Callable[[], str] | None) -> SecureBytes | None:
    """Read a passphrase once on the UI thread and wrap it in ``SecureBytes``.

    Returns None when nothing was typed. The plain-string copy is dropped right
    away so it is never captured by a worker closure or kept on a viewmodel (L7).
    """
    pp_str = get_passphrase().strip() if get_passphrase is not None else ""
    if not pp_str:
        return None
    return secure_from_text(normalise_passphrase(pp_str))


class OperationViewModel(QObject):
    """Base viewmodel for a single background GPG operation.

    Signals
    -------
    operation_succeeded   Carries the result object on success.
    operation_failed      Human-readable error string.
    loading_changed       True while the background worker is running.
    keys_loaded           Keys listed by :meth:`_load_keys`.
    """

    operation_succeeded: Signal = Signal(object)
    operation_failed: Signal = Signal(str)
    loading_changed: Signal = Signal(bool)
    keys_loaded: Signal = Signal(list)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._pool = QThreadPool.globalInstance()

    def _run(
        self,
        do: Callable[[], Any],
        *,
        expect: type | tuple[type, ...],
        secure_result: bool = False,
    ) -> None:
        """Run ``do`` on a worker thread and dispatch its outcome.

        ``operation_succeeded`` fires only when the result is an instance of
        ``expect``. ``secure_result=True`` pulls the result via
        :meth:`Worker.take_result` instead of emitting it through a queued
        ``Signal(object)`` — used by decryption so plaintext is never carried
        across threads inside a Qt signal payload.

        The caller is responsible for emitting ``loading_changed(True)`` before
        invoking this (after any UI-thread passphrase handling); the matching
        ``loading_changed(False)`` is emitted here on completion.
        """
        if secure_result:
            worker = Worker(do, emit_result=False)
            worker.signals.result_ready.connect(
                lambda: self._emit_success(worker.take_result(), expect)
            )
        else:
            worker = Worker(do)
            worker.signals.result.connect(lambda result: self._emit_success(result, expect))
        worker.signals.error.connect(self._on_error)
        worker.signals.finished.connect(self._on_finished)
        self._pool.start(worker)

    def _load_keys(self, key_service: KeyService, *, private_only: bool = False) -> None:
        """List keys on a worker thread and emit them via ``keys_loaded``."""

        def _list() -> list[KeyInfo]:
            keys = key_service.list_keys()
            return [k for k in keys if k.has_private_key] if private_only else keys

        worker = Worker(_list)
        worker.signals.result.connect(self._on_keys)
        worker.signals.error.connect(self._on_error)
        self._pool.start(worker)

    def _on_keys(self, keys: object) -> None:
        if isinstance(keys, list):
            self.keys_loaded.emit(keys)

    def _emit_success(self, result: object, expect: type | tuple[type, ...]) -> None:
        if isinstance(result, expect):
            self.operation_succeeded.emit(result)

    def _on_error(self, message: str) -> None:
        self.operation_failed.emit(message)

    def _on_finished(self) -> None:
        self.loading_changed.emit(False)
