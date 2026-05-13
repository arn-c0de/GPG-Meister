"""Generic background worker for QThreadPool (used by all ViewModels)."""

from __future__ import annotations

import typing
from collections.abc import Callable
from threading import Lock
from typing import Any

from PySide6.QtCore import QObject, QRunnable, Signal


class _Signals(QObject):
    result: Signal = Signal(object)
    error: Signal = Signal(str)
    finished: Signal = Signal()


class Worker(QRunnable):
    """Run a callable in a QThreadPool thread and emit result/error signals."""

    _live_workers: typing.ClassVar[set[Worker]] = set()
    _live_workers_lock = Lock()

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs
        self.signals = _Signals()
        # Keep a Python reference until `run()` completes. Without this, PySide
        # can garbage-collect the QRunnable wrapper before QThreadPool executes it.
        with self._live_workers_lock:
            self._live_workers.add(self)
        self.setAutoDelete(True)

    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
            self.signals.result.emit(result)
        except Exception as exc:
            self.signals.error.emit(str(exc))
        finally:
            self.signals.finished.emit()
            with self._live_workers_lock:
                self._live_workers.discard(self)
