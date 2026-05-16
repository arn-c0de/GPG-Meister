from __future__ import annotations

import base64
import json

import pytest

from gpg_meister.models.kdf_params import KDFAlgorithm
from gpg_meister.models.vault import (
    NONCE_LEN,
    CipherAlgorithm,
    CipherParams,
    KDFFields,
    VaultHeader,
)
from gpg_meister.security.errors import VaultFormatError
from gpg_meister.security.vault_format import (
    MAGIC,
    MAGIC_LEN,
    VAULT_FORMAT_VERSION,
    header_to_canonical_json,
    pack,
    unpack,
)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


@pytest.fixture
def sample_header() -> VaultHeader:
    return VaultHeader(
        kdf=KDFFields(
            algorithm=KDFAlgorithm.ARGON2ID,
            salt_b64=_b64(b"\x01" * 16),
            time_cost=3,
            memory_cost=262_144,
            parallelism=4,
            hash_len=32,
        ),
        cipher=CipherParams(
            algorithm=CipherAlgorithm.CHACHA20_POLY1305,
            nonce_b64=_b64(b"\x02" * NONCE_LEN),
        ),
    )


def test_canonical_json_is_sorted_and_compact(sample_header: VaultHeader) -> None:
    raw = header_to_canonical_json(sample_header)
    # No whitespace between separators.
    assert b": " not in raw
    assert b", " not in raw
    # Top-level keys appear in sorted order.
    parsed = json.loads(raw.decode("utf-8"))
    assert list(parsed.keys()) == sorted(parsed.keys())


def test_canonical_json_is_stable(sample_header: VaultHeader) -> None:
    assert header_to_canonical_json(sample_header) == header_to_canonical_json(sample_header)


def test_roundtrip_preserves_header_and_ciphertext(sample_header: VaultHeader) -> None:
    ct = b"\xab" * 256
    frame, header_bytes = pack(sample_header, ct)
    result = unpack(frame)
    assert result.ciphertext == ct
    assert result.header == sample_header
    assert result.header_bytes == header_bytes


def test_unpack_rejects_wrong_magic(sample_header: VaultHeader) -> None:
    frame, _ = pack(sample_header, b"x")
    bad = b"XXXX" + frame[MAGIC_LEN:]
    with pytest.raises(VaultFormatError, match="magic"):
        unpack(bad)


def test_unpack_rejects_unsupported_version(sample_header: VaultHeader) -> None:
    frame, _ = pack(sample_header, b"x")
    bad = bytearray(frame)
    bad[MAGIC_LEN] = 0x09
    with pytest.raises(VaultFormatError, match="version"):
        unpack(bytes(bad))


def test_unpack_rejects_truncation_in_header(sample_header: VaultHeader) -> None:
    frame, _ = pack(sample_header, b"x")
    with pytest.raises(VaultFormatError):
        unpack(frame[:10])


def test_unpack_rejects_truncation_in_ciphertext(sample_header: VaultHeader) -> None:
    frame, _ = pack(sample_header, b"\xff" * 32)
    with pytest.raises(VaultFormatError):
        unpack(frame[:-1])


def test_unpack_rejects_trailing_garbage(sample_header: VaultHeader) -> None:
    frame, _ = pack(sample_header, b"x")
    with pytest.raises(VaultFormatError, match="trailing"):
        unpack(frame + b"\x00")


def test_unpack_rejects_zero_header_length(sample_header: VaultHeader) -> None:
    # Hand-craft a frame with header length = 0
    bad = MAGIC + bytes([VAULT_FORMAT_VERSION]) + (0).to_bytes(4, "big") + (0).to_bytes(4, "big")
    with pytest.raises(VaultFormatError, match="header length"):
        unpack(bad)


def test_unpack_rejects_invalid_header_json(sample_header: VaultHeader) -> None:
    # Build a frame with a header window that is not valid JSON.
    body = b"not json {"
    frame = (
        MAGIC
        + bytes([VAULT_FORMAT_VERSION])
        + len(body).to_bytes(4, "big")
        + body
        + (0).to_bytes(4, "big")
    )
    with pytest.raises(VaultFormatError, match=r"JSON|header"):
        unpack(frame)


def test_unpack_rejects_oversized_memory_cost() -> None:
    """A forged header must not be able to request 1 TiB of RAM (DoS prevention)."""
    body = (
        b'{"cipher":{"algorithm":"chacha20-poly1305","nonce_b64":"'
        + base64.b64encode(b"\x00" * NONCE_LEN)
        + b'"},"format":"GPGMEISTER_VAULT","kdf":{"algorithm":"argon2id","hash_len":32,'
        b'"memory_cost":999999999,"parallelism":4,"salt_b64":"'
        + base64.b64encode(b"\x00" * 16)
        + b'","time_cost":3},"version":2}'
    )
    frame = (
        MAGIC
        + bytes([VAULT_FORMAT_VERSION])
        + len(body).to_bytes(4, "big")
        + body
        + (0).to_bytes(4, "big")
    )
    with pytest.raises(VaultFormatError):
        unpack(frame)


def test_unpack_rejects_unknown_kdf_algorithm() -> None:
    """Algorithm strings outside the KDFAlgorithm enum must be rejected at the frame
    boundary, not later as a generic validation error."""
    body = (
        b'{"cipher":{"algorithm":"chacha20-poly1305","nonce_b64":"'
        + base64.b64encode(b"\x00" * NONCE_LEN)
        + b'"},"format":"GPGMEISTER_VAULT","kdf":{"algorithm":"evil","hash_len":32,'
        b'"memory_cost":262144,"parallelism":4,"salt_b64":"'
        + base64.b64encode(b"\x00" * 16)
        + b'","time_cost":3},"version":2}'
    )
    frame = (
        MAGIC
        + bytes([VAULT_FORMAT_VERSION])
        + len(body).to_bytes(4, "big")
        + body
        + (0).to_bytes(4, "big")
    )
    with pytest.raises(VaultFormatError):
        unpack(frame)


def test_unpack_rejects_excessive_time_cost() -> None:
    body = (
        b'{"cipher":{"algorithm":"chacha20-poly1305","nonce_b64":"'
        + base64.b64encode(b"\x00" * NONCE_LEN)
        + b'"},"format":"GPGMEISTER_VAULT","kdf":{"algorithm":"argon2id","hash_len":32,'
        b'"memory_cost":262144,"parallelism":4,"salt_b64":"'
        + base64.b64encode(b"\x00" * 16)
        + b'","time_cost":1000},"version":2}'
    )
    frame = (
        MAGIC
        + bytes([VAULT_FORMAT_VERSION])
        + len(body).to_bytes(4, "big")
        + body
        + (0).to_bytes(4, "big")
    )
    with pytest.raises(VaultFormatError):
        unpack(frame)


def test_header_bytes_match_canonical_form(sample_header: VaultHeader) -> None:
    frame, header_bytes = pack(sample_header, b"\x00")
    result = unpack(frame)
    # The bytes returned by unpack() are the same bytes embedded in the frame —
    # critical for AAD reproducibility.
    assert result.header_bytes == header_bytes
    assert result.header_bytes == header_to_canonical_json(sample_header)
