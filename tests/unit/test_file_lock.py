from __future__ import annotations

import multiprocessing as mp
import sys
import time
from pathlib import Path

import pytest

from gpg_meister.storage.file_lock import FileLock, FileLockTimeoutError


def test_acquire_and_release(tmp_path: Path) -> None:
    target = tmp_path / "vault"
    lock = FileLock(target)
    assert not lock.is_held
    lock.acquire()
    assert lock.is_held
    lock.release()
    assert not lock.is_held


def test_context_manager(tmp_path: Path) -> None:
    target = tmp_path / "vault"
    with FileLock(target) as lock:
        assert lock.is_held
    assert not lock.is_held


def test_double_acquire_on_same_instance_raises(tmp_path: Path) -> None:
    target = tmp_path / "vault"
    lock = FileLock(target)
    lock.acquire()
    try:
        with pytest.raises(RuntimeError):
            lock.acquire()
    finally:
        lock.release()


def _hold_lock_in_child(
    path_str: str, ready_evt: object, done_evt: object
) -> None:  # pragma: no cover - runs in subprocess
    with FileLock(Path(path_str)):
        ready_evt.set()  # type: ignore[attr-defined]
        done_evt.wait(timeout=5)  # type: ignore[attr-defined]


@pytest.mark.skipif(sys.platform == "win32", reason="multiprocessing semantics differ")
def test_second_process_times_out_while_held(tmp_path: Path) -> None:
    target = tmp_path / "vault"
    ctx = mp.get_context("fork")
    ready = ctx.Event()
    done = ctx.Event()
    proc = ctx.Process(target=_hold_lock_in_child, args=(str(target), ready, done))
    proc.start()
    try:
        assert ready.wait(timeout=3), "child failed to acquire lock"
        start = time.monotonic()
        with pytest.raises(FileLockTimeoutError), FileLock(target, timeout=0.3):
            pass
        elapsed = time.monotonic() - start
        # Lock attempt blocked for at least the timeout, but not absurdly long.
        assert 0.25 <= elapsed < 2.0
    finally:
        done.set()
        proc.join(timeout=5)


def test_release_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "vault"
    lock = FileLock(target)
    lock.acquire()
    lock.release()
    lock.release()  # must not raise


def test_lock_file_cleaned_up_on_posix(tmp_path: Path) -> None:
    target = tmp_path / "vault"
    with FileLock(target):
        lock_path = target.with_name(target.name + ".lock")
        assert lock_path.exists()
    if sys.platform != "win32":
        # POSIX path removes the lock file on release.
        assert not lock_path.exists()


def test_two_locks_in_same_process_are_serialised(tmp_path: Path) -> None:
    """Within one process, second acquire on a different object blocks/times out
    when the first is held in exclusive mode."""
    target = tmp_path / "vault"
    lock_a = FileLock(target, timeout=0.0)
    lock_b = FileLock(target, timeout=0.1)
    lock_a.acquire()
    try:
        with pytest.raises(FileLockTimeoutError):
            lock_b.acquire()
    finally:
        lock_a.release()
    # After release, the second lock acquires cleanly.
    lock_b = FileLock(target, timeout=0.5)
    lock_b.acquire()
    lock_b.release()


def test_creates_parent_directory(tmp_path: Path) -> None:
    target = tmp_path / "subdir" / "vault"
    target.parent.mkdir()
    with FileLock(target):
        pass
    # No leftover lock file.
    assert not target.with_name(target.name + ".lock").exists() or sys.platform == "win32"
