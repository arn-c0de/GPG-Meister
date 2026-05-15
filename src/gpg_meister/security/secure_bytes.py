"""SecureBytes: short-lived byte buffer with best-effort zeroisation and mlock.

Limitations (documented in planv2.md §4.4):
- CPython may copy bytes internally before the explicit zero-fill. This cannot be
  fully prevented. The architecture minimises the window by keeping SecureBytes
  instances short-lived (use them inside `with` blocks only).
- mlock is best-effort: on platforms without it, or when the RLIMIT_MEMLOCK budget
  is exhausted, the buffer is still created but is not pinned. An info-level entry
  is recorded via the caller.
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from types import TracebackType
from typing import Self

_libc = None
_kernel32 = None
if sys.platform.startswith(("linux", "darwin")):
    try:
        _libc = ctypes.CDLL(None, use_errno=True)
    except OSError:
        _libc = None
elif sys.platform == "win32":
    try:
        _kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        _kernel32 = None


def _try_mlock(buf: ctypes.Array[ctypes.c_char]) -> bool:
    addr = ctypes.addressof(buf)
    n = len(buf)
    if sys.platform == "win32":
        if _kernel32 is None:
            return False
        return bool(_kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(n)))
    if _libc is None or not hasattr(_libc, "mlock"):
        return False
    res: int = _libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(n))
    return bool(res == 0)


def _try_munlock(buf: ctypes.Array[ctypes.c_char]) -> None:
    addr = ctypes.addressof(buf)
    n = len(buf)
    if sys.platform == "win32":
        if _kernel32 is None:
            return
        _kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(n))
        return
    if _libc is None or not hasattr(_libc, "munlock"):
        return
    _libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(n))


class SecureBytes:
    """A bytes-like container that zeros its memory on close.

    Always use as a context manager:

        with SecureBytes.from_bytes(secret) as sb:
            do_work(sb.view())
    """

    __slots__ = ("_buffer", "_closed", "_locked", "_size")

    def __init__(self, size: int) -> None:
        if size < 0:
            raise ValueError("size must be non-negative")
        self._size = size
        # ctypes.create_string_buffer allocates a writable, zero-initialised buffer.
        # We size it to `size + 1` to match create_string_buffer's NUL slot but
        # never expose the NUL byte through `view()`.
        self._buffer: ctypes.Array[ctypes.c_char] = (ctypes.c_char * (size + 1))()
        self._locked = _try_mlock(self._buffer) if size > 0 else False
        self._closed = False

    @classmethod
    def from_bytes(cls, source: bytes) -> Self:
        sb = cls(len(source))
        ctypes.memmove(sb._buffer, source, len(source))
        return sb

    def view(self) -> memoryview:
        """Return a read-write byte memoryview over the buffer.

        Cast to format `'B'` so callers can index and mutate individual bytes
        directly. Raises RuntimeError if the SecureBytes has been closed.
        """
        if self._closed:
            raise RuntimeError("SecureBytes is closed")
        return memoryview(self._buffer).cast("B")[: self._size]

    def to_bytes(self) -> bytes:
        """Return a copy of the buffer's contents as a regular bytes object.

        The caller is responsible for managing the resulting copy — it lives on the
        Python heap and cannot be reliably zeroed. Avoid this method unless an API
        boundary truly requires `bytes`.
        """
        if self._closed:
            raise RuntimeError("SecureBytes is closed")
        return bytes(self.view())

    def __len__(self) -> int:
        return self._size

    def __enter__(self) -> Self:
        if self._closed:
            raise RuntimeError("cannot re-enter a closed SecureBytes")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        try:
            ctypes.memset(self._buffer, 0, len(self._buffer))
        finally:
            if self._locked:
                _try_munlock(self._buffer)
                self._locked = False
            self._closed = True

    def __repr__(self) -> str:
        state = "closed" if self._closed else f"size={self._size}"
        return f"<SecureBytes {state}>"

    def __str__(self) -> str:
        return self.__repr__()

    # Pickling is forbidden — sensitive data must never end up in a serialised stream.
    def __reduce__(self) -> tuple[object, ...]:
        raise TypeError("SecureBytes cannot be pickled")

    def __getstate__(self) -> None:
        raise TypeError("SecureBytes cannot be pickled")

    @property
    def is_locked(self) -> bool:
        return self._locked

    @property
    def is_closed(self) -> bool:
        return self._closed


@contextmanager
def secure_bytes_from(source: bytes) -> Iterator[SecureBytes]:
    """Convenience wrapper: create a SecureBytes from a regular bytes object.

    The caller's original `source` reference is not zeroed by this function — the
    caller must avoid creating long-lived plaintext copies in the first place.
    """
    sb = SecureBytes.from_bytes(source)
    try:
        yield sb
    finally:
        sb.close()
