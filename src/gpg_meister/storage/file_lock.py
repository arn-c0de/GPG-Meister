"""Cross-platform advisory file locking (planv2.md §4.6).

Used by `vault_service` to prevent two app instances from concurrently writing
the same vault file. The lock is *advisory*: cooperating processes that follow
this protocol are serialised; non-cooperating processes can still write the file.

POSIX:    `fcntl.flock` on a dedicated lock file (`<vault>.lock`).
Windows:  `msvcrt.locking` on the same dedicated lock file.

The lock file is kept open for the lifetime of the lock and removed on release
(POSIX) or simply unlocked (Windows). Stale lock files are tolerated — acquiring
the lock removes them.
"""

from __future__ import annotations

import contextlib
import os
import sys
import time
from pathlib import Path
from types import TracebackType

from gpg_meister.storage.permissions import ensure_dir, reject_symlink


class FileLockTimeoutError(TimeoutError):
    """Raised when a lock could not be acquired within the timeout."""


class FileLock:
    """Advisory lock keyed off a path.

    Use as a context manager:

        with FileLock(vault_path, exclusive=True):
            ...
    """

    def __init__(
        self,
        path: Path,
        *,
        exclusive: bool = True,
        timeout: float = 5.0,
        poll_interval: float = 0.05,
    ) -> None:
        self._target = Path(path)
        self._lock_path = self._target.with_name(self._target.name + ".lock")
        self._exclusive = exclusive
        self._timeout = max(0.0, timeout)
        self._poll = max(0.01, poll_interval)
        self._fd: int | None = None

    def acquire(self) -> None:
        """Block until the lock is acquired or `timeout` expires."""
        if self._fd is not None:
            raise RuntimeError("FileLock already acquired")

        ensure_dir(self._lock_path.parent, mode=0o700)
        deadline = time.monotonic() + self._timeout

        # O_NOFOLLOW prevents following a symlink swapped in between the parent
        # ensure_dir check and this open, closing the TOCTOU window.
        open_flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            open_flags |= os.O_NOFOLLOW
        try:
            self._fd = os.open(str(self._lock_path), open_flags, 0o600)
        except OSError as exc:
            raise RuntimeError(
                f"refusing to open possible symlink as lock file: {self._lock_path}"
            ) from exc

        if sys.platform == "win32":
            self._acquire_windows(deadline)
        else:
            self._acquire_posix(deadline)

    def _acquire_posix(self, deadline: float) -> None:
        import fcntl

        if self._fd is None:
            raise RuntimeError("FileLock file descriptor is not open")
        op = fcntl.LOCK_EX if self._exclusive else fcntl.LOCK_SH
        open_flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            open_flags |= os.O_NOFOLLOW
        while True:
            try:
                fcntl.flock(self._fd, op | fcntl.LOCK_NB)
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    self._close_fd()
                    raise FileLockTimeoutError(
                        f"could not acquire lock on {self._target} within "
                        f"{self._timeout}s"
                    ) from None
                time.sleep(self._poll)
                continue

            # After acquiring the lock, verify that the fd and the current
            # filesystem path refer to the same inode.  If a previous holder
            # deleted the lock file between our open() and flock(), a racing
            # process could have created a new lock file and acquired their own
            # lock — making our lock meaningless.  Re-opening and retrying
            # closes this window.
            try:
                fd_stat = os.fstat(self._fd)
                path_stat = os.stat(str(self._lock_path))
            except OSError:
                # Lock file was removed; re-open and retry.
                self._close_fd()
                self._fd = os.open(str(self._lock_path), open_flags, 0o600)
                continue

            if fd_stat.st_ino != path_stat.st_ino or fd_stat.st_dev != path_stat.st_dev:
                # Different inode — lock file was replaced; re-open and retry.
                self._close_fd()
                self._fd = os.open(str(self._lock_path), open_flags, 0o600)
                continue

            return

    def _acquire_windows(self, deadline: float) -> None:  # pragma: no cover
        import importlib

        msvcrt = importlib.import_module("msvcrt")

        if self._fd is None:
            raise RuntimeError("FileLock file descriptor is not open")
        # msvcrt.locking only supports byte-range locks. Lock the first byte.
        while True:
            try:
                os.lseek(self._fd, 0, 0)
                msvcrt.locking(self._fd, msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    self._close_fd()
                    raise FileLockTimeoutError(
                        f"could not acquire lock on {self._target} within "
                        f"{self._timeout}s"
                    ) from None
                time.sleep(self._poll)

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            if sys.platform == "win32":  # pragma: no cover
                import importlib

                msvcrt = importlib.import_module("msvcrt")
                os.lseek(self._fd, 0, 0)
                with contextlib.suppress(OSError):
                    msvcrt.locking(self._fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                with contextlib.suppress(OSError):
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            self._close_fd()
            # Best-effort cleanup of the lock file. Tolerate concurrent removal.
            if sys.platform != "win32":
                with contextlib.suppress(FileNotFoundError, OSError):
                    self._lock_path.unlink()

    def _close_fd(self) -> None:
        if self._fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._fd)
            self._fd = None

    @property
    def is_held(self) -> bool:
        return self._fd is not None

    def __enter__(self) -> FileLock:
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()
