"""Generic background worker for QThreadPool (used by all ViewModels)."""

from __future__ import annotations

import typing
from collections.abc import Callable
from threading import Lock
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QTimer, Signal

from gpg_meister.ui.errors.error_catalog import message_for_exception


class _Signals(QObject):
    result: Signal = Signal(object)
    result_ready: Signal = Signal()
    error: Signal = Signal(str)
    finished: Signal = Signal()


class Worker(QRunnable):
    """Run a callable in a QThreadPool thread and emit result/error signals."""

    _live_workers: typing.ClassVar[set[Worker]] = set()
    _live_workers_lock = Lock()

    def __init__(
        self,
        fn: Callable[..., Any],
        *args: Any,
        emit_result: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self._emit_result = emit_result
        self._result: Any = None
        self._has_result = False
        self._result_lock = Lock()
        self.signals = _Signals()
        # Keep a Python reference until queued signals are delivered on the main
        # thread. Without this, PySide can garbage-collect the QRunnable and its
        # _Signals QObject before the cross-thread signal events are processed,
        # causing Qt to silently drop them.
        with self._live_workers_lock:
            self._live_workers.add(self)
        self.setAutoDelete(True)

    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
            with self._result_lock:
                self._result = result
                self._has_result = True
            self.signals.result_ready.emit()
            if self._emit_result:
                self.signals.result.emit(result)
        except Exception as exc:
            self.signals.error.emit(message_for_exception(exc))
        finally:
            self.signals.finished.emit()
            # Schedule removal on the main thread via a zero-delay timer.
            # This guarantees the queued result/finished signal events (posted
            # above) are delivered *before* this worker is removed from the live
            # set and potentially garbage-collected together with self.signals.
            QTimer.singleShot(0, self._release)

    def _release(self) -> None:
        with self._live_workers_lock:
            self._live_workers.discard(self)

    def take_result(self) -> Any:
        """Return and clear the worker result without sending it through Qt."""
        with self._result_lock:
            if not self._has_result:
                return None
            result = self._result
            self._result = None
            self._has_result = False
            return result
