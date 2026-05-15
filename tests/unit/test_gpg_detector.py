from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

from gpg_meister.startup import gpg_detector
from gpg_meister.startup.gpg_detector import (
    DetectionReason,
    GPGDetectionError,
    detect,
    diagnostics,
)


def _make_fake_gpg(tmp_path: Path, *, content: bytes = b"#!/bin/sh\necho gpg\n") -> Path:
    fake = tmp_path / "gpg"
    fake.write_bytes(content)
    fake.chmod(0o755)
    return fake


def test_user_override_outside_whitelist_requires_trusted_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _make_fake_gpg(tmp_path)
    monkeypatch.setattr(gpg_detector, "_check_parent_writability", lambda _path: None)
    with pytest.raises(GPGDetectionError) as exc:
        detect(user_override_path=str(fake), trusted_hash=None)
    assert exc.value.reason is DetectionReason.USER_OVERRIDE_UNTRUSTED


def test_user_override_with_matching_hash_accepted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _make_fake_gpg(tmp_path)
    monkeypatch.setattr(gpg_detector, "_check_parent_writability", lambda _path: None)
    sha = hashlib.sha256(fake.read_bytes()).hexdigest()
    result = detect(user_override_path=str(fake), trusted_hash=sha, trusted_path=str(fake))
    assert result.path == fake.resolve()
    assert result.sha256 == sha
    assert not result.is_whitelisted


def test_user_override_with_wrong_hash_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _make_fake_gpg(tmp_path)
    monkeypatch.setattr(gpg_detector, "_check_parent_writability", lambda _path: None)
    with pytest.raises(GPGDetectionError) as exc:
        detect(user_override_path=str(fake), trusted_hash="0" * 64, trusted_path=str(fake))
    assert exc.value.reason is DetectionReason.HASH_MISMATCH


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_group_or_world_writable_binary_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _make_fake_gpg(tmp_path)
    monkeypatch.setattr(gpg_detector, "_check_parent_writability", lambda _path: None)
    sha = hashlib.sha256(fake.read_bytes()).hexdigest()
    # Make group-writable.
    fake.chmod(stat.S_IRWXU | stat.S_IRWXG)  # 0o770
    with pytest.raises(GPGDetectionError) as exc:
        detect(user_override_path=str(fake), trusted_hash=sha, trusted_path=str(fake))
    assert exc.value.reason is DetectionReason.WORLD_WRITABLE


def test_missing_override_path_raises(tmp_path: Path) -> None:
    with pytest.raises(GPGDetectionError) as exc:
        detect(user_override_path=str(tmp_path / "does-not-exist"))
    assert exc.value.reason is DetectionReason.NOT_FOUND


def test_no_whitelist_match_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Force an empty whitelist for this test so the real system GPG cannot satisfy it.
    monkeypatch.setattr(gpg_detector, "_platform_whitelist", lambda: ())
    with pytest.raises(GPGDetectionError) as exc:
        detect()
    assert exc.value.reason is DetectionReason.NOT_FOUND


def test_whitelist_match_returns_detection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _make_fake_gpg(tmp_path)
    monkeypatch.setattr(gpg_detector, "_check_parent_writability", lambda _path: None)
    monkeypatch.setattr(gpg_detector, "_check_root_owned", lambda _path: True)
    monkeypatch.setattr(gpg_detector, "_platform_whitelist", lambda: (fake,))
    result = detect()
    assert result.path == fake.resolve()
    assert result.is_whitelisted
    assert result.sha256 == hashlib.sha256(fake.read_bytes()).hexdigest()


def test_symlink_to_outside_whitelist_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real = _make_fake_gpg(real_dir)
    link_target_dir = tmp_path / "linked"
    link_target_dir.mkdir()
    link = link_target_dir / "gpg"
    link.symlink_to(real)
    # Whitelist lists the link path, but its canonical target is outside the
    # whitelist set — must be refused.
    monkeypatch.setattr(gpg_detector, "_platform_whitelist", lambda: (link,))
    monkeypatch.setattr(gpg_detector, "_check_root_owned", lambda _path: True)
    with pytest.raises(GPGDetectionError) as exc:
        detect()
    assert exc.value.reason is DetectionReason.NOT_FOUND


def test_diagnostics_contains_keys() -> None:
    info = diagnostics()
    assert "platform" in info
    assert "whitelist" in info
    assert "path_candidates" in info


def test_real_gpg_detected_when_present() -> None:
    """If the host has GnuPG installed, the default detect() must succeed."""
    # Sanity-check the real environment — skipped if no GPG is installed.
    import shutil

    if shutil.which("gpg") is None and shutil.which("gpg2") is None:
        pytest.skip("no GnuPG installed in the test environment")
    result = detect()
    assert result.path.is_absolute()
    assert len(result.sha256) == 64
    assert os.path.exists(result.path)
