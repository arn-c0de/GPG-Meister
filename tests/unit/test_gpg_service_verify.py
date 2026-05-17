from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess

from gpg_meister.services.gpg_service import GPGService, GPGServiceConfig


def test_detached_verify_uses_gpg_home_for_temp_signature(tmp_path: Path) -> None:
    service = GPGService.__new__(GPGService)
    service._config = GPGServiceConfig(binary_path=tmp_path / "gpg", home_dir=tmp_path / "gnupg")
    service._binary_dev = None
    service._binary_ino = None
    service._config.home_dir.mkdir(mode=0o700)
    captured_sig_path: Path | None = None
    captured_data_path: Path | None = None

    def _fake_run_gpg(args: list[str], **_: object) -> CompletedProcess[bytes]:
        nonlocal captured_sig_path, captured_data_path
        captured_sig_path = Path(args[1])
        captured_data_path = Path(args[2])
        assert captured_sig_path.read_bytes() == b"sig"
        assert captured_data_path.read_bytes() == b"payload"
        return CompletedProcess(
            args,
            0,
            b"",
            b"[GNUPG:] VALIDSIG " + (b"A" * 40) + b" 0 0 0 0 0 0 0 0 0\n",
        )

    service._run_gpg = _fake_run_gpg  # type: ignore[method-assign]

    valid, fingerprint, signed_at = service.verify(b"payload", detached_signature=b"sig")

    assert valid is True
    assert fingerprint == "A" * 40
    assert signed_at is not None
    assert captured_sig_path is not None
    assert captured_data_path is not None
    assert captured_sig_path.parent == service._config.home_dir
    assert captured_data_path.parent == service._config.home_dir
    assert not captured_sig_path.exists()
    assert not captured_data_path.exists()
