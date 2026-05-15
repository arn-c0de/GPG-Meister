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
    loop = QEventLoop()
    seen: list[tuple[str, object]] = []

    worker = Worker(lambda: 123)
    worker.signals.result.connect(lambda value: seen.append(("result", value)))
    worker.signals.error.connect(lambda message: seen.append(("error", message)))
    worker.signals.finished.connect(loop.quit)
    QThreadPool.globalInstance().start(worker)

    del worker
    gc.collect()

    QTimer.singleShot(5000, loop.quit)
    deadline = time.monotonic() + 5.0
    while not seen and time.monotonic() < deadline:
        loop.exec()
        app.processEvents()

    assert seen == [("result", 123)]
