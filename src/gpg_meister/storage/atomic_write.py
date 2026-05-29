"""Atomic file write helpers (planv2.md §4.6).

The vault write path must guarantee that an observer never sees a half-written
vault file at the destination path. This module provides:

- `atomic_write_bytes(path, data, mode=0o600)`: write `data` into `<path>.tmp` in
  the same directory, `fsync()` the file, `os.replace()` the tmp file onto `path`,
  and `fsync()` the parent directory so the rename is durable.
- `AtomicWriter`: a context manager for cases where the caller wants to stream
  data through a file handle (and still get the atomic rename at the end).

On Windows, parent-directory `fsync` is a no-op because the win32 file API does
not support it; `os.replace` is still atomic.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import sys
from pathlib import Path
from types import TracebackType
from typing import IO


def _dir_fsync(directory: Path) -> None:
    """Best-effort directory fsync so the rename is durable on crash.

    No-op on Windows (the platform does not support directory fsync).
    """
    if sys.platform == "win32":
        return
    fd = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _tmp_path(target: Path) -> Path:
    """Build a unique temp path in the same directory as `target`.

    A short random suffix avoids collisions between two atomic writes to the same
    base name from different processes.
    """
    suffix = secrets.token_hex(4)
    return target.with_name(f".{target.name}.{suffix}.tmp")


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Write `data` to `path` atomically.

    Steps:
      1. Open a fresh tmp file in the same directory with the requested mode.
      2. Write all bytes, flush, fsync the file descriptor.
      3. os.replace(tmp, path) — atomic on POSIX and Win32 for files on the
         same volume.
      4. fsync the parent directory so the rename survives a crash (POSIX).
      5. On any failure, the tmp file is removed.
    """
    path = Path(path)
    if not path.parent.exists():
        raise FileNotFoundError(f"parent directory does not exist: {path.parent}")

    tmp = _tmp_path(path)
    fd = os.open(
        str(tmp),
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        mode,
    )
    # os.open's mode is masked by the process umask, so enforce the exact mode
    # on the fd. This also means the new file's mode is independent of (and not
    # weakened by) any pre-existing target's mode, since os.replace adopts the
    # tmp file's metadata.
    if sys.platform != "win32":
        with contextlib.suppress(OSError):
            os.fchmod(fd, mode)
    try:
        try:
            with os.fdopen(fd, "wb", closefd=True) as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
            raise

        try:
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
            raise

        with contextlib.suppress(OSError):
            _dir_fsync(path.parent)
    finally:
        # If something went sideways and we still have a tmp file, clean it up.
        if tmp.exists():
            with contextlib.suppress(OSError):
                tmp.unlink()


class AtomicWriter:
    """Context manager streaming variant of `atomic_write_bytes`.

    Usage:

        with AtomicWriter(target_path) as fh:
            fh.write(chunk_one)
            fh.write(chunk_two)
        # target_path is now updated atomically; on exception, no change is made.
    """

    def __init__(self, path: Path, *, mode: int = 0o600) -> None:
        self._target = Path(path)
        if not self._target.parent.exists():
            raise FileNotFoundError(
                f"parent directory does not exist: {self._target.parent}"
            )
        self._tmp = _tmp_path(self._target)
        self._mode = mode
        self._fh: IO[bytes] | None = None
        self._committed = False

    def __enter__(self) -> AtomicWriter:
        fd = os.open(
            str(self._tmp),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            self._mode,
        )
        if sys.platform != "win32":
            with contextlib.suppress(OSError):
                os.fchmod(fd, self._mode)
        self._fh = os.fdopen(fd, "wb", closefd=True)
        return self

    def write(self, data: bytes) -> int:
        if self._fh is None:
            raise RuntimeError("AtomicWriter not entered")
        return self._fh.write(data)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._fh is None:
            return
        try:
            try:
                self._fh.flush()
                if exc_type is None:
                    os.fsync(self._fh.fileno())
            finally:
                self._fh.close()

            if exc_type is None:
                os.replace(self._tmp, self._target)
                with contextlib.suppress(OSError):
                    _dir_fsync(self._target.parent)
                self._committed = True
        finally:
            if not self._committed and self._tmp.exists():
                with contextlib.suppress(OSError):
                    self._tmp.unlink()


__all__ = ["AtomicWriter", "atomic_write_bytes"]
