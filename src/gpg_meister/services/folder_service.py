"""Encrypt and decrypt whole folders.

A folder is packed into a tar archive and the archive is encrypted with GPG,
either to recipient keys or symmetrically with a passphrase. Decryption reverses
that and unpacks the archive into a destination directory.

The plaintext archive exists only briefly on disk, as a ``0600`` temp file next
to the output, and is removed whatever the outcome. Unpacking accepts nothing
but regular files and directories that stay inside one top-level folder, so a
crafted archive cannot write outside the destination (path traversal, links,
device files).
"""

from __future__ import annotations

import contextlib
import os
import shutil
import tarfile
import tempfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.gpg_service import GPGService
from gpg_meister.services.message_service import enforce_recipient_policy
from gpg_meister.services.validation import validate_fingerprint
from gpg_meister.storage.audit_log import OUTCOME_FAILED, OUTCOME_OK, AuditLog

ENCRYPTED_FOLDER_SUFFIX = ".tar.gpg"


@dataclass(frozen=True)
class FolderDecryptResult:
    folder: Path
    decrypted_with_fingerprint: str | None


class FolderService:
    def __init__(self, *, gpg: GPGService, audit: AuditLog) -> None:
        self._gpg = gpg
        self._audit = audit

    def encrypt_folder(
        self,
        folder: Path,
        target: Path,
        *,
        recipient_fingerprints: Sequence[str] = (),
        passphrase: SecureBytes | None = None,
        trust_confirmed: bool = False,
    ) -> Path:
        """Encrypt ``folder`` into ``target`` with recipient keys or a passphrase."""
        folder = folder.resolve()
        target = target.resolve()
        if not folder.is_dir() or not folder.name:
            raise ValueError("choose an existing folder to encrypt")
        if target.is_relative_to(folder):
            raise ValueError("the encrypted file must be saved outside the folder")
        recipients = tuple(validate_fingerprint(fp) for fp in recipient_fingerprints)
        if recipients:
            enforce_recipient_policy(self._gpg, recipients, trust_confirmed=trust_confirmed)
        elif passphrase is None:
            raise ValueError("choose a recipient key or enter a passphrase")

        with _temp_file(target.parent) as archive:
            file_count = _pack(folder, archive)
            self._gpg.encrypt_file(
                archive,
                target,
                recipient_fingerprints=recipients,
                passphrase=None if recipients else passphrase,
                always_trust=trust_confirmed,
            )
        self._audit.emit(
            "folder_encrypted",
            outcome=OUTCOME_OK,
            mode="key" if recipients else "passphrase",
            recipient_count=len(recipients),
            file_count=file_count,
        )
        return target

    def decrypt_folder(
        self,
        source: Path,
        destination: Path,
        *,
        passphrase: SecureBytes | None = None,
    ) -> FolderDecryptResult:
        """Decrypt ``source`` and unpack the folder it holds into ``destination``."""
        source = source.resolve()
        destination = destination.resolve()
        if not source.is_file():
            raise ValueError("choose an existing encrypted folder file")
        if not destination.is_dir():
            raise ValueError("choose an existing destination folder")

        try:
            with _temp_file(destination) as archive:
                decrypted_with = self._gpg.decrypt_file(source, archive, passphrase=passphrase)
                folder = _unpack(archive, destination)
        except Exception as exc:
            self._audit.emit(
                "folder_decrypt_failed",
                outcome=OUTCOME_FAILED,
                reason=type(exc).__name__,
            )
            raise
        self._audit.emit(
            "folder_decrypted",
            outcome=OUTCOME_OK,
            decrypted_with=decrypted_with or "",
        )
        return FolderDecryptResult(folder=folder, decrypted_with_fingerprint=decrypted_with)


@contextlib.contextmanager
def _temp_file(directory: Path) -> Iterator[Path]:
    """A private (``0600``) temp file in ``directory``, removed on exit."""
    fd, name = tempfile.mkstemp(prefix=".gpg-meister-", suffix=".tar", dir=directory)
    os.close(fd)
    try:
        yield Path(name)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(name)


def _pack(folder: Path, archive: Path) -> int:
    """Write ``folder`` into ``archive``; return the number of files packed.

    Symlinks and special files are skipped: following a link could pull in data
    from outside the folder, and the unpacker would refuse them anyway.
    """
    file_count = 0

    def _regular_only(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        nonlocal file_count
        if info.isfile():
            file_count += 1
        elif not info.isdir():
            return None
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        return info

    with tarfile.open(archive, "w") as tar:
        tar.add(folder, arcname=folder.name, filter=_regular_only)
    return file_count


def _unpack(archive: Path, destination: Path) -> Path:
    """Unpack ``archive`` into ``destination``; return the created folder."""
    try:
        with tarfile.open(archive, "r:") as tar:
            return _extract(tar, destination)
    except tarfile.TarError:
        raise ValueError("the decrypted file is not a valid encrypted folder") from None


def _extract(tar: tarfile.TarFile, destination: Path) -> Path:
    members = tar.getmembers()
    root = _archive_root(members)
    final = destination / root
    if final.exists():
        raise ValueError(f'"{root}" already exists in the destination folder')

    # Unpack into a staging directory first so a failure halfway through
    # never leaves a partial folder under the final name.
    staging = Path(tempfile.mkdtemp(prefix=".gpg-meister-", dir=destination))
    try:
        for member in members:
            path = (staging / member.name).resolve()
            if not path.is_relative_to(staging):
                raise ValueError("the encrypted folder contains an unsafe path")
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:  # pragma: no cover - isfile() guarantees data
                raise ValueError("the encrypted folder is damaged")
            with source, open(path, "xb") as out:
                shutil.copyfileobj(source, out)
        (staging / root).rename(final)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return final


def _archive_root(members: Sequence[tarfile.TarInfo]) -> str:
    """The single top-level folder name every member must live under."""
    if not members:
        raise ValueError("the encrypted folder is empty")
    roots = set()
    for member in members:
        if not (member.isfile() or member.isdir()):
            raise ValueError("the encrypted folder contains links or special files")
        name = PurePosixPath(member.name)
        if name.is_absolute() or ".." in name.parts or "\\" in member.name:
            raise ValueError("the encrypted folder contains an unsafe path")
        roots.add(name.parts[0])
    if len(roots) != 1:
        raise ValueError("the encrypted folder must contain exactly one top-level folder")
    root = roots.pop()
    if not members[0].isdir() or members[0].name != root:
        raise ValueError("the encrypted folder must contain exactly one top-level folder")
    return root
