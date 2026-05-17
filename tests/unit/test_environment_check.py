from __future__ import annotations

import ctypes
from pathlib import Path
from types import SimpleNamespace

from pytest import MonkeyPatch

from gpg_meister.startup import environment_check as env


def test_memlock_limit_warning_when_hard_limit_is_low(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(env, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(env, "_memlock_hard_limit", lambda: 64 * 1024)

    warnings = env.check_memlock_limit()

    assert [warning.code for warning in warnings] == ["memlock_limit_low"]


def test_check_mlock_false_when_hard_limit_is_low(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(env, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(env, "_memlock_hard_limit", lambda: 64 * 1024)

    assert env.check_mlock() is False


def test_dm_crypt_detection_walks_parent_slaves(tmp_path: Path) -> None:
    sys_block = tmp_path / "block"
    dm_swap = sys_block / "dm-1"
    dm_luks = sys_block / "dm-0"
    backing = sys_block / "nvme0n1p2"
    (dm_swap / "slaves").mkdir(parents=True)
    (dm_luks / "dm").mkdir(parents=True)
    (dm_luks / "slaves").mkdir()
    backing.mkdir(parents=True)
    (dm_swap / "slaves" / "dm-0").symlink_to(dm_luks)
    (dm_luks / "slaves" / "nvme0n1p2").symlink_to(backing)
    (dm_luks / "dm" / "uuid").write_text("CRYPT-LUKS2-example\n", encoding="utf-8")

    assert env._is_dm_crypt_device("/dev/dm-1", sys_block_root=sys_block) is True


def test_disable_core_dumps_uses_rlimit_and_prctl(monkeypatch: MonkeyPatch) -> None:
    calls: list[tuple[object, object]] = []
    monkeypatch.setattr(env, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(
        env,
        "resource",
        SimpleNamespace(
            RLIMIT_CORE=4,
            setrlimit=lambda which, limits: calls.append((which, limits)),
        ),
    )
    monkeypatch.setattr(
        ctypes,
        "CDLL",
        lambda *_args, **_kwargs: SimpleNamespace(prctl=lambda *_args: 0),
    )

    assert env.disable_core_dumps() is True
    assert calls == [(4, (0, 0))]


def test_disable_core_dumps_fails_when_prctl_fails(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(env, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(env, "resource", None)
    monkeypatch.setattr(
        ctypes,
        "CDLL",
        lambda *_args, **_kwargs: SimpleNamespace(prctl=lambda *_args: -1),
    )

    assert env.disable_core_dumps() is False
