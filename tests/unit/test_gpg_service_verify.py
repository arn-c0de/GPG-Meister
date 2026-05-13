from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from gpg_meister.services.gpg_service import GPGService, GPGServiceConfig


@dataclass
class _FakeVerifyResult:
    valid: bool = True
    fingerprint: str = "A" * 40
    timestamp: str = "0"


class _FakeGPG:
    def __init__(self) -> None:
        self.sig_path: Path | None = None

    def verify_data(self, sig_path: str, data: bytes) -> _FakeVerifyResult:
        self.sig_path = Path(sig_path)
        return _FakeVerifyResult()


def test_detached_verify_uses_gpg_home_for_temp_signature(tmp_path: Path) -> None:
    service = GPGService.__new__(GPGService)
    service._config = GPGServiceConfig(binary_path=tmp_path / "gpg", home_dir=tmp_path / "gnupg")
    service._gpg = _FakeGPG()
    service._config.home_dir.mkdir(mode=0o700)

    valid, fingerprint, signed_at = service.verify(b"payload", detached_signature=b"sig")

    assert valid is True
    assert fingerprint == "A" * 40
    assert signed_at is not None
    assert service._gpg.sig_path is not None
    assert service._gpg.sig_path.parent == service._config.home_dir
    assert not service._gpg.sig_path.exists()
