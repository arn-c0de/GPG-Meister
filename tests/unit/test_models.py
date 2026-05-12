from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from gpg_meister.models import (
    NONCE_LEN,
    VAULT_FORMAT_TAG,
    CipherAlgorithm,
    CipherParams,
    KDFFields,
    KDFParams,
    KDFProfile,
    KeyAlgorithm,
    KeyInfo,
    TrustLevel,
    VaultHeader,
    VaultKeyEntry,
    VaultManifest,
    balanced_params,
    high_memory_params,
    params_for_profile,
)

VALID_FP = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _now_utc() -> datetime:
    return datetime.now(UTC)


def test_key_info_uppercases_fingerprint() -> None:
    info = KeyInfo(
        fingerprint=VALID_FP.lower(),
        user_ids=("Alice <a@example.org>",),
        algorithm=KeyAlgorithm.EDDSA,
        length=255,
        created_at=_now_utc(),
    )
    assert info.fingerprint == VALID_FP


def test_key_info_rejects_short_fingerprint() -> None:
    with pytest.raises(ValidationError):
        KeyInfo(
            fingerprint="ABCD",
            user_ids=("u",),
            algorithm=KeyAlgorithm.RSA,
            length=4096,
            created_at=_now_utc(),
        )


def test_key_info_rejects_non_hex_fingerprint() -> None:
    with pytest.raises(ValidationError):
        KeyInfo(
            fingerprint="G" + VALID_FP[1:],
            user_ids=("u",),
            algorithm=KeyAlgorithm.RSA,
            length=4096,
            created_at=_now_utc(),
        )


def test_key_info_is_expired_when_past() -> None:
    past = _now_utc() - timedelta(days=1)
    info = KeyInfo(
        fingerprint=VALID_FP,
        user_ids=("u",),
        algorithm=KeyAlgorithm.RSA,
        length=4096,
        created_at=past - timedelta(days=1),
        expires_at=past,
    )
    assert info.is_expired


def test_key_info_is_not_expired_when_no_expiry() -> None:
    info = KeyInfo(
        fingerprint=VALID_FP,
        user_ids=("u",),
        algorithm=KeyAlgorithm.RSA,
        length=4096,
        created_at=_now_utc(),
    )
    assert not info.is_expired


def test_kdf_high_memory_params_match_rfc9106() -> None:
    p = high_memory_params()
    assert p.time_cost == 3
    assert p.memory_cost == 262_144
    assert p.parallelism == 4
    assert p.hash_len == 32
    assert p.salt_len == 16


def test_kdf_floor_rejects_weak_params() -> None:
    with pytest.raises(ValidationError):
        KDFParams(
            time_cost=1,
            memory_cost=1024,
            parallelism=1,
            hash_len=16,
            salt_len=8,
        )


def test_params_for_profile_returns_distinct_profiles() -> None:
    high = params_for_profile(KDFProfile.HIGH_MEMORY)
    bal = params_for_profile(KDFProfile.BALANCED)
    assert high.memory_cost > bal.memory_cost
    assert bal == balanced_params()


def test_cipher_params_rejects_wrong_nonce_length() -> None:
    with pytest.raises(ValidationError):
        CipherParams(algorithm=CipherAlgorithm.CHACHA20_POLY1305, nonce_b64=_b64(b"\x00" * 8))


def test_cipher_params_accepts_correct_nonce() -> None:
    nonce = b"\xab" * NONCE_LEN
    cp = CipherParams(algorithm=CipherAlgorithm.CHACHA20_POLY1305, nonce_b64=_b64(nonce))
    assert cp.nonce == nonce


def test_vault_header_rejects_unknown_format() -> None:
    with pytest.raises(ValidationError):
        VaultHeader(
            format="OTHER",
            version=2,
            kdf=KDFFields(
                algorithm="argon2id",
                salt_b64=_b64(b"\x00" * 16),
                time_cost=3,
                memory_cost=262_144,
                parallelism=4,
                hash_len=32,
            ),
            cipher=CipherParams(
                algorithm=CipherAlgorithm.CHACHA20_POLY1305,
                nonce_b64=_b64(b"\x00" * NONCE_LEN),
            ),
        )


def test_vault_header_accepts_default_format() -> None:
    h = VaultHeader(
        kdf=KDFFields(
            algorithm="argon2id",
            salt_b64=_b64(b"\x00" * 16),
            time_cost=3,
            memory_cost=262_144,
            parallelism=4,
            hash_len=32,
        ),
        cipher=CipherParams(
            algorithm=CipherAlgorithm.CHACHA20_POLY1305,
            nonce_b64=_b64(b"\x00" * NONCE_LEN),
        ),
    )
    assert h.format == VAULT_FORMAT_TAG
    assert h.version == 2


def test_vault_key_entry_repr_redacts_private_key() -> None:
    entry = VaultKeyEntry(
        fingerprint=VALID_FP,
        user_ids=("Alice <a@example.org>",),
        public_key_armored="-----BEGIN PGP PUBLIC KEY BLOCK-----\n…",
        private_key_armored="-----BEGIN PGP PRIVATE KEY BLOCK-----\nSECRET",
        has_private_key=True,
        created_at=_now_utc(),
    )
    text = repr(entry)
    assert "SECRET" not in text
    assert "<redacted>" in text


def test_vault_manifest_repr_redacts_keys() -> None:
    manifest = VaultManifest(
        created_by="alice",
        created_at=_now_utc(),
        app_version="0.1.0",
        description="dev",
        keys=(
            VaultKeyEntry(
                fingerprint=VALID_FP,
                user_ids=("u",),
                public_key_armored="pub",
                private_key_armored="PRIVATE_SECRET",
                has_private_key=True,
                created_at=_now_utc(),
            ),
        ),
    )
    text = repr(manifest)
    assert "PRIVATE_SECRET" not in text
    assert "<redacted>" in text


def test_trust_level_round_trip() -> None:
    assert TrustLevel("full") is TrustLevel.FULL
