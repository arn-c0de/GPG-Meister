"""Integration tests against a real, isolated GnuPG keyring.

Skipped automatically when no `gpg`/`gpg2` binary is on PATH.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from gpg_meister.models.key_info import KeyAlgorithm
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.errors import (
    GPGKeyNotFoundError,
    GPGPassphraseError,
)
from gpg_meister.services.gpg_service import GPGService

if TYPE_CHECKING:
    pass

pytestmark = pytest.mark.integration


def _gen_eddsa(service: GPGService, name: str = "Alice", email: str = "alice@example.org") -> str:
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        return service.generate_key(
            name=name,
            email=email,
            algorithm=KeyAlgorithm.EDDSA,
            length=255,
            expiry="2y",
            passphrase=pw,
        )


def test_generate_key_returns_fingerprint(isolated_gpg: GPGService) -> None:
    fp = _gen_eddsa(isolated_gpg)
    assert len(fp) == 40
    assert fp == fp.upper()


def test_list_keys_after_generate(isolated_gpg: GPGService) -> None:
    fp = _gen_eddsa(isolated_gpg)
    keys = isolated_gpg.list_keys()
    assert any(k.fingerprint == fp for k in keys)


def test_find_key_not_present_raises(isolated_gpg: GPGService) -> None:
    with pytest.raises(GPGKeyNotFoundError):
        isolated_gpg.find_key("0" * 40)


def test_export_public_key_returns_armored(isolated_gpg: GPGService) -> None:
    fp = _gen_eddsa(isolated_gpg)
    armored = isolated_gpg.export_public_key(fp)
    assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in armored
    assert "-----END PGP PUBLIC KEY BLOCK-----" in armored


def test_export_private_key_requires_passphrase(isolated_gpg: GPGService) -> None:
    fp = _gen_eddsa(isolated_gpg)
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        armored = isolated_gpg.export_private_key(fp, pw)
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in armored


def test_export_private_key_wrong_passphrase_raises(isolated_gpg: GPGService) -> None:
    fp = _gen_eddsa(isolated_gpg)
    with SecureBytes.from_bytes(b"wrong passphrase") as pw, pytest.raises(GPGPassphraseError):
        isolated_gpg.export_private_key(fp, pw)


def test_encrypt_decrypt_roundtrip(isolated_gpg: GPGService) -> None:
    fp = _gen_eddsa(isolated_gpg)
    plaintext = b"hello, encrypted world"
    ciphertext = isolated_gpg.encrypt(plaintext, recipient_fingerprints=[fp])
    assert "-----BEGIN PGP MESSAGE-----" in ciphertext
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        decrypted, signer, valid = isolated_gpg.decrypt(ciphertext.encode("utf-8"), passphrase=pw)
    assert decrypted == plaintext
    assert signer is None  # we did not sign
    assert valid is False


def test_encrypt_decrypt_with_signature(isolated_gpg: GPGService) -> None:
    fp = _gen_eddsa(isolated_gpg)
    plaintext = b"signed and encrypted"
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        ciphertext = isolated_gpg.encrypt(
            plaintext,
            recipient_fingerprints=[fp],
            sign_with=fp,
            passphrase=pw,
        )
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        decrypted, signer, valid = isolated_gpg.decrypt(ciphertext.encode("utf-8"), passphrase=pw)
    assert decrypted == plaintext
    assert signer is not None
    assert valid is True


def test_import_public_key_from_other_keyring(
    isolated_gpg: GPGService, tmp_path: Path
) -> None:
    from gpg_meister.services.gpg_service import GPGService, GPGServiceConfig

    fp = _gen_eddsa(isolated_gpg)
    armored = isolated_gpg.export_public_key(fp)

    # Spin up a second, fully isolated keyring and import the public key into it.
    other_home = tmp_path / "other"
    other_home.mkdir(mode=0o700)
    other = GPGService(
        GPGServiceConfig(binary_path=isolated_gpg.config.binary_path, home_dir=other_home)
    )
    imported = other.import_key(armored)
    assert fp in imported
    assert any(k.fingerprint == fp for k in other.list_keys())


def test_version_returns_tuple(isolated_gpg: GPGService) -> None:
    v = isolated_gpg.version()
    assert isinstance(v, tuple)
    assert len(v) >= 2
    assert all(isinstance(x, int) for x in v)
    assert v >= (2, 0)


def test_passphrase_never_in_argv(
    isolated_gpg: GPGService, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hardening invariant from planv2.md §5.6: the passphrase must never be
    visible in argv of any subprocess we spawn."""
    import subprocess
    from typing import Any

    captured_argvs: list[list[str]] = []
    original_popen = subprocess.Popen

    class SnoopingPopen(original_popen):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            argv = args[0] if args else kwargs.get("args", [])
            if isinstance(argv, (list, tuple)):
                captured_argvs.append([str(x) for x in argv])
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", SnoopingPopen)

    # Generate a key + decrypt to exercise multiple passphrase paths.
    fp = _gen_eddsa(isolated_gpg)
    ciphertext = isolated_gpg.encrypt(b"x", recipient_fingerprints=[fp])
    with SecureBytes.from_bytes(b"correct horse battery staple") as pw:
        isolated_gpg.decrypt(ciphertext.encode("utf-8"), passphrase=pw)

    needle = "correct horse battery staple"
    for argv in captured_argvs:
        for item in argv:
            assert needle not in item, f"passphrase leaked into argv: {argv!r}"
