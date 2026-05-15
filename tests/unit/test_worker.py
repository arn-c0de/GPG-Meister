from __future__ import annotations

import gc
import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QThreadPool, QTimer
from PySide6.QtWidgets import QApplication

from gpg_meister.ui.worker import Worker


def test_worker_completes_without_caller_retaining_reference() -> None:
    app = QApplication.instance() or QApplication([])
    seen: list[tuple[str, object]] = []

    worker = Worker(lambda: 123)
    worker.signals.result.connect(lambda value: seen.append(("result", value)))
    worker.signals.error.connect(lambda message: seen.append(("error", message)))
    QThreadPool.globalInstance().start(worker)

    del worker
    gc.collect()

    # Pump the event loop for up to 5 seconds. The worker's QTimer.singleShot(0)
    # ensures signals are delivered before the worker is released, so 5 s is
    # more than enough even under heavy load from prior tests.
    deadline = time.monotonic() + 5.0
    while not seen and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)

    assert seen == [("result", 123)]
