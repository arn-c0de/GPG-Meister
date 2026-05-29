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

from gpg_meister.ui.worker import Worker


class OperationViewModel(QObject):
    """Base viewmodel for a single background GPG operation.

    Signals
    -------
    operation_succeeded   Carries the result object on success.
    operation_failed      Human-readable error string.
    loading_changed       True while the background worker is running.
    """

    operation_succeeded: Signal = Signal(object)
    operation_failed: Signal = Signal(str)
    loading_changed: Signal = Signal(bool)

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

    def _emit_success(self, result: object, expect: type | tuple[type, ...]) -> None:
        if isinstance(result, expect):
            self.operation_succeeded.emit(result)

    def _on_error(self, message: str) -> None:
        self.operation_failed.emit(message)

    def _on_finished(self) -> None:
        self.loading_changed.emit(False)
