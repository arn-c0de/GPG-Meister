"""Slot wrapping for a GPG key's passphrase — the crypto half, no hardware."""

from __future__ import annotations

import base64
import secrets

import pytest
from pydantic import ValidationError

from gpg_meister.models.kdf_params import (
    MIN_MEMORY_COST_KB,
    MIN_SALT_LEN,
    MIN_TIME_COST,
    KDFParams,
)
from gpg_meister.models.key_unlock import (
    FidoCredential,
    KeyUnlockSlot,
    UnlockSlotType,
    has_emergency_passphrase,
)
from gpg_meister.security.aead import decrypt as aead_decrypt
from gpg_meister.security.errors import DecryptionError
from gpg_meister.security.key_unlock import (
    KEY_SECRET_TEXT_LEN,
    TOKEN_SECRET_LEN,
    generate_key_secret,
    slot_associated_data,
    unwrap_with_passphrase,
    unwrap_with_token,
    wrap_with_passphrase,
    wrap_with_token,
)
from gpg_meister.security.secure_bytes import SecureBytes

# Cheapest parameters the policy allows; these tests exercise wiring, not cost.
CHEAP = KDFParams(
    time_cost=MIN_TIME_COST,
    memory_cost=MIN_MEMORY_COST_KB,
    parallelism=1,
    hash_len=32,
    salt_len=MIN_SALT_LEN,
)


def _credential(**overrides: object) -> FidoCredential:
    base: dict[str, object] = {
        "credential_id_b64": base64.b64encode(b"\xab" * 64).decode("ascii"),
        "salt_b64": base64.b64encode(b"\xcd" * 32).decode("ascii"),
        "rp_id": "gpg-meister.local",
        "label": "YubiKey",
    }
    base.update(overrides)
    return FidoCredential(**base)  # type: ignore[arg-type]


def _token_secret(fill: bytes = b"\x11") -> SecureBytes:
    return SecureBytes.from_bytes(fill * TOKEN_SECRET_LEN)


# ------------------------------------------------------------ the secret itself


def test_the_generated_secret_is_pipe_safe_text() -> None:
    """GnuPG reads the passphrase from a pipe up to a newline.

    Raw random bytes would eventually contain 0x0a and truncate the passphrase
    for *some* keys only — so the secret is base64 text, and must stay that way.
    """
    with generate_key_secret() as secret:
        raw = secret.to_bytes()

    assert len(raw) == KEY_SECRET_TEXT_LEN
    assert b"\n" not in raw
    assert base64.b64decode(raw, validate=True)


def test_two_generated_secrets_differ() -> None:
    with generate_key_secret() as first, generate_key_secret() as second:
        assert first.to_bytes() != second.to_bytes()


# ------------------------------------------------------------- passphrase slots


def test_a_passphrase_slot_round_trips() -> None:
    with generate_key_secret() as secret:
        expected = secret.to_bytes()
        with SecureBytes.from_bytes(b"correct horse") as pw:
            slot = wrap_with_passphrase(secret, pw, params=CHEAP)
            recovered = unwrap_with_passphrase(slot, pw, params=CHEAP)

    with recovered:
        assert recovered.to_bytes() == expected


def test_a_wrong_passphrase_is_rejected() -> None:
    with generate_key_secret() as secret, SecureBytes.from_bytes(b"right") as pw:
        slot = wrap_with_passphrase(secret, pw, params=CHEAP)

    with SecureBytes.from_bytes(b"wrong") as bad, pytest.raises(DecryptionError):
        unwrap_with_passphrase(slot, bad, params=CHEAP)


def test_a_tampered_passphrase_slot_is_rejected() -> None:
    with generate_key_secret() as secret, SecureBytes.from_bytes(b"pw") as pw:
        slot = wrap_with_passphrase(secret, pw, params=CHEAP)

    flipped = bytearray(slot.wrapped_secret)
    flipped[0] ^= 0x01
    tampered = slot.model_copy(
        update={"wrapped_secret_b64": base64.b64encode(bytes(flipped)).decode("ascii")}
    )

    with SecureBytes.from_bytes(b"pw") as pw, pytest.raises(DecryptionError):
        unwrap_with_passphrase(tampered, pw, params=CHEAP)


# ------------------------------------------------------------------- FIDO slots


def test_a_token_slot_round_trips() -> None:
    credential = _credential()
    with generate_key_secret() as secret:
        expected = secret.to_bytes()
        with _token_secret() as token:
            slot = wrap_with_token(secret, token, credential=credential)
        with _token_secret() as token_again:
            recovered = unwrap_with_token(slot, token_again)

    with recovered:
        assert recovered.to_bytes() == expected
    assert slot.fido == credential
    assert slot.label == "YubiKey"


def test_a_different_token_cannot_open_the_slot() -> None:
    """The whole premise: another token derives a different PRF output."""
    with generate_key_secret() as secret, _token_secret(b"\x11") as token:
        slot = wrap_with_token(secret, token, credential=_credential())

    with _token_secret(b"\x22") as other, pytest.raises(DecryptionError):
        unwrap_with_token(slot, other)


def test_a_token_secret_of_the_wrong_size_is_refused() -> None:
    """It is used as the AEAD key unchanged, so its length is not negotiable."""
    with (
        generate_key_secret() as secret,
        SecureBytes.from_bytes(b"short") as token,
        pytest.raises(ValueError, match="exactly"),
    ):
        wrap_with_token(secret, token, credential=_credential())


# --------------------------------------------------------------- slot confusion


def test_the_two_slot_kinds_use_different_associated_data() -> None:
    assert slot_associated_data(UnlockSlotType.PASSPHRASE) != slot_associated_data(
        UnlockSlotType.FIDO
    )


def test_a_wrapped_secret_cannot_be_replayed_across_slot_kinds() -> None:
    """A FIDO slot's ciphertext must not open as a passphrase slot's.

    Both kinds wrap the same 44-byte secret under a 32-byte key, so without the
    domain separator the ciphertexts would be interchangeable — an attacker who
    could swap them would turn "needs the token" into "needs a passphrase I
    chose". Proven at the AEAD layer, with the *correct* key: only the
    associated data differs, and that alone must make it fail.
    """
    with generate_key_secret() as secret, _token_secret() as token:
        slot = wrap_with_token(secret, token, credential=_credential())

        with pytest.raises(DecryptionError):
            aead_decrypt(
                ciphertext=slot.wrapped_secret,
                key=token,
                nonce=slot.nonce,
                associated_data=slot_associated_data(UnlockSlotType.PASSPHRASE),
            )


def test_a_passphrase_slot_without_kdf_parameters_is_invalid() -> None:
    with pytest.raises(ValidationError, match="KDF parameters"):
        KeyUnlockSlot(
            type=UnlockSlotType.PASSPHRASE,
            wrapped_secret_b64=base64.b64encode(b"x" * 60).decode("ascii"),
            nonce_b64=base64.b64encode(b"n" * 12).decode("ascii"),
        )


def test_a_fido_slot_must_not_carry_kdf_parameters() -> None:
    with generate_key_secret() as secret, SecureBytes.from_bytes(b"pw") as pw:
        passphrase_slot = wrap_with_passphrase(secret, pw, params=CHEAP)

    with pytest.raises(ValidationError, match="must not carry KDF"):
        KeyUnlockSlot(
            type=UnlockSlotType.FIDO,
            wrapped_secret_b64=passphrase_slot.wrapped_secret_b64,
            nonce_b64=passphrase_slot.nonce_b64,
            kdf=passphrase_slot.kdf,
            fido=_credential(),
        )


def test_a_fido_slot_needs_its_binding() -> None:
    with pytest.raises(ValidationError, match="needs its token binding"):
        KeyUnlockSlot(
            type=UnlockSlotType.FIDO,
            wrapped_secret_b64=base64.b64encode(b"x" * 60).decode("ascii"),
            nonce_b64=base64.b64encode(b"n" * 12).decode("ascii"),
        )


# ------------------------------------------------------------------- the binding


def test_a_prf_salt_must_be_32_bytes() -> None:
    with pytest.raises(ValidationError, match="32 bytes"):
        _credential(salt_b64=base64.b64encode(secrets.token_bytes(16)).decode("ascii"))


def test_an_empty_credential_id_is_refused() -> None:
    with pytest.raises(ValidationError, match="must not be empty"):
        _credential(credential_id_b64="")


def test_an_existing_passphrase_can_be_wrapped_unchanged() -> None:
    """Binding an existing key must not rewrite it.

    The slot seals whatever passphrase the key already has, so enrolling a token
    for an old key needs no GPG operation at all — only a new slot.
    """
    existing = b"the passphrase I picked in 2019"
    with SecureBytes.from_bytes(existing) as secret, _token_secret() as token:
        slot = wrap_with_token(secret, token, credential=_credential())
    with _token_secret() as token, unwrap_with_token(slot, token) as recovered:
        assert recovered.to_bytes() == existing


@pytest.mark.parametrize("bad", [b"has\nnewline", b"has\x00nul", b"has\rreturn"])
def test_a_secret_with_framing_bytes_is_refused(bad: bytes) -> None:
    """These would truncate or terminate the passphrase on its way to GnuPG.

    Caught at wrap time so the key is never sealed behind a secret that cannot
    be delivered — the alternative is a slot that fails only at unlock.
    """
    with (
        SecureBytes.from_bytes(bad) as secret,
        _token_secret() as token,
        pytest.raises(ValueError, match="NUL or newline"),
    ):
        wrap_with_token(secret, token, credential=_credential())


def test_an_oversized_secret_is_refused() -> None:
    with (
        SecureBytes.from_bytes(b"x" * 500) as secret,
        _token_secret() as token,
        pytest.raises(ValueError, match="1 to"),
    ):
        wrap_with_token(secret, token, credential=_credential())


def test_emergency_passphrase_is_detected() -> None:
    with generate_key_secret() as secret, SecureBytes.from_bytes(b"pw") as pw:
        pass_slot = wrap_with_passphrase(secret, pw, params=CHEAP)
        with _token_secret() as token:
            token_slot = wrap_with_token(secret, token, credential=_credential())

    assert has_emergency_passphrase((pass_slot, token_slot))
    assert not has_emergency_passphrase((token_slot,))
