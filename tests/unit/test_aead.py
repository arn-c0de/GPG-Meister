from __future__ import annotations

import pytest

from gpg_meister.models.vault import CipherAlgorithm
from gpg_meister.security.aead import KEY_LEN, decrypt, encrypt, generate_nonce
from gpg_meister.security.errors import DecryptionError
from gpg_meister.security.secure_bytes import SecureBytes


@pytest.fixture
def key_bytes() -> bytes:
    return b"\x11" * KEY_LEN


@pytest.fixture
def other_key_bytes() -> bytes:
    return b"\x22" * KEY_LEN


@pytest.mark.parametrize(
    "cipher", [CipherAlgorithm.CHACHA20_POLY1305, CipherAlgorithm.AES_256_GCM]
)
def test_roundtrip(cipher: CipherAlgorithm, key_bytes: bytes) -> None:
    nonce = generate_nonce()
    aad = b"header-bytes"
    plaintext = b"hello, world"
    with SecureBytes.from_bytes(key_bytes) as k:
        ct = encrypt(plaintext, k, nonce, aad, cipher)
        pt = decrypt(ct, k, nonce, aad, cipher)
    assert pt == plaintext


@pytest.mark.parametrize(
    "cipher", [CipherAlgorithm.CHACHA20_POLY1305, CipherAlgorithm.AES_256_GCM]
)
def test_tampered_ciphertext_raises(cipher: CipherAlgorithm, key_bytes: bytes) -> None:
    nonce = generate_nonce()
    aad = b"header"
    with SecureBytes.from_bytes(key_bytes) as k:
        ct = bytearray(encrypt(b"secret", k, nonce, aad, cipher))
        ct[0] ^= 0x01
        with pytest.raises(DecryptionError):
            decrypt(bytes(ct), k, nonce, aad, cipher)


@pytest.mark.parametrize(
    "cipher", [CipherAlgorithm.CHACHA20_POLY1305, CipherAlgorithm.AES_256_GCM]
)
def test_tampered_aad_raises(cipher: CipherAlgorithm, key_bytes: bytes) -> None:
    nonce = generate_nonce()
    with SecureBytes.from_bytes(key_bytes) as k:
        ct = encrypt(b"secret", k, nonce, b"header-A", cipher)
        with pytest.raises(DecryptionError):
            decrypt(ct, k, nonce, b"header-B", cipher)


@pytest.mark.parametrize(
    "cipher", [CipherAlgorithm.CHACHA20_POLY1305, CipherAlgorithm.AES_256_GCM]
)
def test_wrong_key_raises(
    cipher: CipherAlgorithm, key_bytes: bytes, other_key_bytes: bytes
) -> None:
    nonce = generate_nonce()
    aad = b"aad"
    with SecureBytes.from_bytes(key_bytes) as k1, SecureBytes.from_bytes(other_key_bytes) as k2:
        ct = encrypt(b"secret", k1, nonce, aad, cipher)
        with pytest.raises(DecryptionError):
            decrypt(ct, k2, nonce, aad, cipher)


def test_wrong_key_length_raises() -> None:
    nonce = generate_nonce()
    with SecureBytes.from_bytes(b"\x00" * 16) as k, pytest.raises(DecryptionError):
        encrypt(b"x", k, nonce, b"", CipherAlgorithm.CHACHA20_POLY1305)


def test_wrong_nonce_length_raises(key_bytes: bytes) -> None:
    with SecureBytes.from_bytes(key_bytes) as k, pytest.raises(DecryptionError):
        encrypt(b"x", k, b"\x00" * 8, b"", CipherAlgorithm.CHACHA20_POLY1305)


def test_closed_key_raises(key_bytes: bytes) -> None:
    k = SecureBytes.from_bytes(key_bytes)
    k.close()
    with pytest.raises(DecryptionError):
        encrypt(b"x", k, generate_nonce(), b"", CipherAlgorithm.CHACHA20_POLY1305)


def test_generate_nonce_length() -> None:
    assert len(generate_nonce()) == 12
    assert generate_nonce() != generate_nonce()


def test_error_message_is_generic(key_bytes: bytes, other_key_bytes: bytes) -> None:
    """Error must not distinguish wrong-key vs tampered-ciphertext (planv2.md §4.2)."""
    nonce = generate_nonce()
    aad = b"aad"
    with SecureBytes.from_bytes(key_bytes) as k1, SecureBytes.from_bytes(other_key_bytes) as k2:
        ct = encrypt(b"secret", k1, nonce, aad, CipherAlgorithm.CHACHA20_POLY1305)
        try:
            decrypt(ct, k2, nonce, aad, CipherAlgorithm.CHACHA20_POLY1305)
        except DecryptionError as wrong_key_exc:
            wrong_key_msg = str(wrong_key_exc)
        else:
            raise AssertionError("expected DecryptionError")

        ct_tampered = bytearray(encrypt(b"secret", k1, nonce, aad, CipherAlgorithm.CHACHA20_POLY1305))
        ct_tampered[-1] ^= 0xFF
        try:
            decrypt(bytes(ct_tampered), k1, nonce, aad, CipherAlgorithm.CHACHA20_POLY1305)
        except DecryptionError as tamper_exc:
            tamper_msg = str(tamper_exc)
        else:
            raise AssertionError("expected DecryptionError")

    assert wrong_key_msg == tamper_msg
