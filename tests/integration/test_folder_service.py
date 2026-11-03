from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from gpg_meister.models.key_info import KeyAlgorithm
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.errors import GPGPassphraseError
from gpg_meister.services.folder_service import FolderService, _unpack
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.services.key_service import KeyService
from gpg_meister.storage.audit_log import AuditLog

pytestmark = pytest.mark.integration

_PASSPHRASE = b"correct horse battery staple"


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.log")


@pytest.fixture
def folders(isolated_gpg: GPGService, audit: AuditLog) -> FolderService:
    return FolderService(gpg=isolated_gpg, audit=audit)


@pytest.fixture
def source(tmp_path: Path) -> Path:
    folder = tmp_path / "work" / "project"
    (folder / "sub").mkdir(parents=True)
    (folder / "a.txt").write_text("hello")
    (folder / "sub" / "b.bin").write_bytes(bytes(range(256)))
    return folder


def _assert_same_tree(original: Path, restored: Path) -> None:
    assert restored.name == original.name
    assert (restored / "a.txt").read_text() == "hello"
    assert (restored / "sub" / "b.bin").read_bytes() == bytes(range(256))


def _out(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    out.mkdir()
    return out


def test_passphrase_round_trip(folders: FolderService, source: Path, tmp_path: Path) -> None:
    target = tmp_path / "project.tar.gpg"
    with SecureBytes.from_bytes(_PASSPHRASE) as pw:
        folders.encrypt_folder(source, target, passphrase=pw)
    assert target.read_bytes()[:1] != b"-"  # binary, not armored
    assert b"hello" not in target.read_bytes()

    out = _out(tmp_path)
    with SecureBytes.from_bytes(_PASSPHRASE) as pw:
        result = folders.decrypt_folder(target, out, passphrase=pw)
    _assert_same_tree(source, result.folder)
    assert result.decrypted_with_fingerprint is None
    # No plaintext archive is left behind.
    assert [p.name for p in out.iterdir()] == ["project"]


def test_wrong_passphrase_is_rejected(
    folders: FolderService, source: Path, tmp_path: Path, audit: AuditLog
) -> None:
    target = tmp_path / "project.tar.gpg"
    with SecureBytes.from_bytes(_PASSPHRASE) as pw:
        folders.encrypt_folder(source, target, passphrase=pw)
    out = _out(tmp_path)
    with SecureBytes.from_bytes(b"wrong passphrase entirely") as pw, pytest.raises(
        GPGPassphraseError
    ):
        folders.decrypt_folder(target, out, passphrase=pw)
    assert list(out.iterdir()) == []
    audit.close()
    events = [json.loads(line)["event"] for line in audit.path.read_text().splitlines()]
    assert "folder_decrypt_failed" in events


def test_key_round_trip(
    folders: FolderService, isolated_gpg: GPGService, audit: AuditLog, source: Path, tmp_path: Path
) -> None:
    with SecureBytes.from_bytes(_PASSPHRASE) as pw:
        key = KeyService(gpg=isolated_gpg, audit=audit).create(
            name="Alice",
            email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA,
            length=255,
            expiry="2y",
            passphrase=pw,
        )
    target = tmp_path / "project.tar.gpg"
    folders.encrypt_folder(source, target, recipient_fingerprints=[key.fingerprint])

    out = _out(tmp_path)
    with SecureBytes.from_bytes(_PASSPHRASE) as pw:
        result = folders.decrypt_folder(target, out, passphrase=pw)
    _assert_same_tree(source, result.folder)
    assert result.decrypted_with_fingerprint


def test_existing_destination_is_not_overwritten(
    folders: FolderService, source: Path, tmp_path: Path
) -> None:
    target = tmp_path / "project.tar.gpg"
    with SecureBytes.from_bytes(_PASSPHRASE) as pw:
        folders.encrypt_folder(source, target, passphrase=pw)
    out = _out(tmp_path)
    (out / "project").mkdir()
    with SecureBytes.from_bytes(_PASSPHRASE) as pw, pytest.raises(ValueError, match="exists"):
        folders.decrypt_folder(target, out, passphrase=pw)


def test_target_inside_folder_is_rejected(folders: FolderService, source: Path) -> None:
    with SecureBytes.from_bytes(_PASSPHRASE) as pw, pytest.raises(ValueError, match="outside"):
        folders.encrypt_folder(source, source / "self.tar.gpg", passphrase=pw)


def test_needs_recipient_or_passphrase(folders: FolderService, source: Path, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="recipient"):
        folders.encrypt_folder(source, tmp_path / "x.tar.gpg")


# ------------------------------------------------------------- safe unpacking


def _archive(tmp_path: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> Path:
    path = tmp_path / "crafted.tar"
    with tarfile.open(path, "w") as tar:
        for info, data in members:
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data) if info.isfile() else None)
    return path


def _dir(name: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    return info


@pytest.mark.parametrize("evil", ["root/../../escape.txt", "/abs.txt", "other/x.txt"])
def test_unpack_rejects_paths_outside_the_root(tmp_path: Path, evil: str) -> None:
    archive = _archive(tmp_path, [(_dir("root"), b""), (tarfile.TarInfo(evil), b"x")])
    out = _out(tmp_path)
    with pytest.raises(ValueError):
        _unpack(archive, out)
    assert list(out.iterdir()) == []


def test_unpack_rejects_links(tmp_path: Path) -> None:
    link = tarfile.TarInfo("root/link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    archive = _archive(tmp_path, [(_dir("root"), b""), (link, b"")])
    with pytest.raises(ValueError, match="links"):
        _unpack(archive, _out(tmp_path))


def test_unpack_rejects_non_archive(tmp_path: Path) -> None:
    bogus = tmp_path / "plain.txt"
    bogus.write_text("not a tar")
    with pytest.raises(ValueError, match="not a valid encrypted folder"):
        _unpack(bogus, _out(tmp_path))
