from __future__ import annotations

import os
from pathlib import Path

from gpg_meister.models.message import SignatureStatus
from gpg_meister.services.gpg_service import (
    GPGService,
    GPGServiceConfig,
    _decryption_fingerprint,
    _evaluate_signature,
    _GPGRun,
    _parse_status,
    _write_all,
)


def test_detached_verify_uses_gpg_home_for_temp_signature(tmp_path: Path) -> None:
    service = GPGService.__new__(GPGService)
    service._config = GPGServiceConfig(binary_path=tmp_path / "gpg", home_dir=tmp_path / "gnupg")
    service._binary_dev = None
    service._binary_ino = None
    service._config.home_dir.mkdir(mode=0o700)
    captured_sig_path: Path | None = None
    captured_data_path: Path | None = None

    def _fake_run_gpg(args: list[str], **_: object) -> _GPGRun:
        nonlocal captured_sig_path, captured_data_path
        captured_sig_path = Path(args[1])
        captured_data_path = Path(args[2])
        assert captured_sig_path.read_bytes() == b"sig"
        assert captured_data_path.read_bytes() == b"payload"
        return _GPGRun(
            args=tuple(args),
            returncode=0,
            stdout=b"",
            stderr=b"",
            status=(
                b"[GNUPG:] GOODSIG DEADBEEF signer\n"
                b"[GNUPG:] VALIDSIG " + (b"A" * 40) + b" 2020-01-01 1577836800 0 4 0 1 8 01 "
                + (b"A" * 40) + b"\n"
            ),
        )

    service._run_gpg = _fake_run_gpg  # type: ignore[assignment,method-assign]

    status, fingerprint, signed_at = service.verify(b"payload", detached_signature=b"sig")

    assert status is SignatureStatus.VALID
    assert fingerprint == "A" * 40
    assert signed_at is not None
    assert captured_sig_path is not None
    assert captured_data_path is not None
    assert captured_sig_path.parent == service._config.home_dir
    assert captured_data_path.parent == service._config.home_dir
    assert not captured_sig_path.exists()
    assert not captured_data_path.exists()


def _records(*lines: str) -> list[list[str]]:
    blob = "".join(f"[GNUPG:] {line}\n" for line in lines).encode()
    return _parse_status(blob)


def test_evaluate_signature_valid_requires_goodsig_and_validsig() -> None:
    fpr = "A" * 40
    status, signer, _ = _evaluate_signature(
        _records("GOODSIG DEADBEEF signer", f"VALIDSIG {fpr} 2020-01-01 1577836800 0")
    )
    assert status is SignatureStatus.VALID
    assert signer == fpr


def test_evaluate_signature_revoked_key_is_not_valid() -> None:
    fpr = "B" * 40
    # gpg emits REVKEYSIG *and* VALIDSIG and still exits 0 for a revoked signer.
    status, signer, _ = _evaluate_signature(
        _records("REVKEYSIG DEADBEEF signer", f"VALIDSIG {fpr} 2020-01-01 1577836800 0")
    )
    assert status is SignatureStatus.REVOKED_KEY
    assert status.is_valid is False
    assert signer == fpr  # fingerprint still surfaced for attribution


def test_evaluate_signature_expired_key_is_not_valid() -> None:
    status, _, _ = _evaluate_signature(
        _records("EXPKEYSIG DEADBEEF signer", "VALIDSIG " + "C" * 40 + " 2020-01-01 1577836800 0")
    )
    assert status is SignatureStatus.EXPIRED_KEY
    assert status.is_valid is False


def test_evaluate_signature_bad_signature() -> None:
    status, _, _ = _evaluate_signature(_records("BADSIG DEADBEEF signer"))
    assert status is SignatureStatus.INVALID


def test_evaluate_signature_none_when_unsigned() -> None:
    status, signer, _ = _evaluate_signature(_records("ENC_TO DEADBEEF 1 0"))
    assert status is SignatureStatus.NONE
    assert signer is None


def test_decryption_fingerprint_uses_decryption_key_status() -> None:
    fpr = "E" * 40
    assert (
        _decryption_fingerprint(_records("ENC_TO DEADBEEF 1 0", f"DECRYPTION_KEY {fpr} {fpr}"))
        == fpr
    )


def test_evaluate_signature_lone_validsig_is_not_trusted() -> None:
    # A VALIDSIG without the companion GOODSIG must not be reported valid.
    status, _, _ = _evaluate_signature(
        _records("VALIDSIG " + "D" * 40 + " 2020-01-01 1577836800 0")
    )
    assert status is SignatureStatus.ERROR


def test_write_all_accepts_memoryview_without_buffered_writer() -> None:
    read_fd, write_fd = os.pipe()
    try:
        data = bytearray(b"secret-passphrase")
        _write_all(write_fd, memoryview(data))
        os.close(write_fd)
        write_fd = -1

        assert os.read(read_fd, 1024) == b"secret-passphrase"
    finally:
        if write_fd >= 0:
            os.close(write_fd)
        os.close(read_fd)
