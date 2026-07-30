"""Binding keys to tokens and unlocking them, with GPG and the token stubbed."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from gpg_meister.models.kdf_params import (
    MIN_MEMORY_COST_KB,
    MIN_SALT_LEN,
    MIN_TIME_COST,
    KDFParams,
)
from gpg_meister.models.key_info import KeyAlgorithm
from gpg_meister.models.key_unlock import FidoCredential
from gpg_meister.security.key_unlock import TOKEN_SECRET_LEN
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.errors import GPGProcessError
from gpg_meister.services.fido_service import FidoPinError, FidoTouchError
from gpg_meister.services.key_unlock_service import (
    KeyUnlockError,
    KeyUnlockService,
    NoUnlockMethodError,
)
from gpg_meister.storage.metadata_store import MetadataStore

FPR = "A" * 40
OTHER_FPR = "B" * 40

CHEAP = KDFParams(
    time_cost=MIN_TIME_COST,
    memory_cost=MIN_MEMORY_COST_KB,
    parallelism=1,
    hash_len=32,
    salt_len=MIN_SALT_LEN,
)


def _credential(tag: bytes = b"\xab") -> FidoCredential:
    return FidoCredential(
        credential_id_b64=base64.b64encode(tag * 64).decode("ascii"),
        salt_b64=base64.b64encode(b"\xcd" * 32).decode("ascii"),
        rp_id="gpg-meister.local",
        label="YubiKey",
    )


class _FakeFido:
    """A token that derives one fixed secret per credential id."""

    def __init__(self, *, enroll_error: Exception | None = None) -> None:
        self.enroll_error = enroll_error
        self.derive_errors: list[Exception | None] = []
        self.derive_calls = 0
        self.credential = _credential()

    def enroll(self, *, pin: SecureBytes, user_label: str, on_touch: object = None) -> tuple:
        if self.enroll_error is not None:
            raise self.enroll_error
        return self.credential, self._secret_for(self.credential)

    def derive(
        self, credential: FidoCredential, *, pin: SecureBytes, on_touch: object = None
    ) -> SecureBytes:
        self.derive_calls += 1
        if self.derive_errors:
            error = self.derive_errors.pop(0)
            if error is not None:
                raise error
        return self._secret_for(credential)

    @staticmethod
    def _secret_for(credential: FidoCredential) -> SecureBytes:
        # Deterministic stand-in for the token's PRF: same credential in, same
        # 32 bytes out; a different credential yields different bytes.
        seed = credential.credential_id[:1] or b"\x00"
        return SecureBytes.from_bytes(seed * TOKEN_SECRET_LEN)


class _FakeGPG:
    def __init__(self, *, fingerprint: str = FPR, sign_fails: bool = False) -> None:
        self.fingerprint = fingerprint
        self.sign_fails = sign_fails
        self.generated_passphrase: bytes | None = None
        self.deleted: list[str] = []

    def generate_key(self, *, passphrase: SecureBytes, **_kw: object) -> str:
        self.generated_passphrase = passphrase.to_bytes()
        return self.fingerprint

    def sign(self, data: bytes, *, fingerprint: str, passphrase: SecureBytes) -> str:
        if self.sign_fails:
            raise GPGProcessError("bad passphrase")
        return "-----BEGIN PGP SIGNATURE-----"

    def delete_key(
        self, fingerprint: str, *, including_secret: bool = False, passphrase: object = None
    ) -> None:
        self.deleted.append(fingerprint)


@pytest.fixture
def store(tmp_path: Path) -> MetadataStore:
    with MetadataStore(tmp_path / "metadata.sqlite3") as opened:
        yield opened


def _service(store: MetadataStore, gpg: _FakeGPG, fido: _FakeFido) -> KeyUnlockService:
    return KeyUnlockService(
        gpg=gpg,  # type: ignore[arg-type]
        fido=fido,  # type: ignore[arg-type]
        store=store,
        kdf_params=CHEAP,
    )


def _pin() -> SecureBytes:
    return SecureBytes.from_bytes(b"123456")


# -------------------------------------------------------------- creating a key


def test_a_new_key_is_created_with_a_secret_only_the_token_holds(
    store: MetadataStore,
) -> None:
    gpg, fido = _FakeGPG(), _FakeFido()

    with _pin() as pin, SecureBytes.from_bytes(b"emergency") as fallback:
        fingerprint = _service(store, gpg, fido).create_key_with_token(
            name="Alice",
            email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA,
            length=0,
            expiry="0",
            pin=pin,
            emergency_passphrase=fallback,
        )

    assert fingerprint == FPR
    # The key's passphrase is generated, not anything the user typed.
    assert gpg.generated_passphrase is not None
    assert gpg.generated_passphrase != b"emergency"
    methods = _service(store, gpg, fido).methods_for(FPR)
    assert methods.has_token
    assert methods.has_passphrase
    assert not methods.is_token_only


def test_the_token_recovers_exactly_the_generated_passphrase(store: MetadataStore) -> None:
    """The point of the whole exercise, end to end through the slots."""
    gpg, fido = _FakeGPG(), _FakeFido()
    service = _service(store, gpg, fido)

    with _pin() as pin:
        service.create_key_with_token(
            name="Alice",
            email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA,
            length=0,
            expiry="0",
            pin=pin,
            emergency_passphrase=None,
        )
        with service.unlock_with_token(FPR, pin=pin) as recovered:
            assert recovered.to_bytes() == gpg.generated_passphrase


def test_the_emergency_passphrase_recovers_the_same_secret(store: MetadataStore) -> None:
    gpg, fido = _FakeGPG(), _FakeFido()
    service = _service(store, gpg, fido)

    with _pin() as pin, SecureBytes.from_bytes(b"emergency") as fallback:
        service.create_key_with_token(
            name="Alice",
            email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA,
            length=0,
            expiry="0",
            pin=pin,
            emergency_passphrase=fallback,
        )

    with (
        SecureBytes.from_bytes(b"emergency") as fallback,
        service.unlock_with_passphrase(FPR, fallback) as recovered,
    ):
        assert recovered.to_bytes() == gpg.generated_passphrase


def test_a_token_only_key_has_no_passphrase_way_in(store: MetadataStore) -> None:
    gpg, fido = _FakeGPG(), _FakeFido()
    service = _service(store, gpg, fido)

    with _pin() as pin:
        service.create_key_with_token(
            name="Alice",
            email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA,
            length=0,
            expiry="0",
            pin=pin,
            emergency_passphrase=None,
        )

    assert service.methods_for(FPR).is_token_only
    with SecureBytes.from_bytes(b"guess") as guess, pytest.raises(NoUnlockMethodError):
        service.unlock_with_passphrase(FPR, guess)


def test_a_key_whose_slots_cannot_be_stored_is_deleted_again(
    store: MetadataStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dangerous case: the key exists, its passphrase was never written down.

    Nobody — not the token, not the user — could ever open it again, so it must
    not be left sitting in the keyring looking like a usable key.
    """
    gpg, fido = _FakeGPG(), _FakeFido()

    def _explode(*_args: object, **_kw: object) -> int:
        raise RuntimeError("disk full")

    monkeypatch.setattr(store, "add_unlock_slot", _explode)

    with _pin() as pin, pytest.raises(RuntimeError):
        _service(store, gpg, fido).create_key_with_token(
            name="Alice",
            email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA,
            length=0,
            expiry="0",
            pin=pin,
            emergency_passphrase=None,
        )

    assert gpg.deleted == [FPR]


def test_a_partly_written_slot_set_is_rolled_back(
    store: MetadataStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Half a slot set could silently turn a fallback key into a token-only one."""
    gpg, fido = _FakeGPG(), _FakeFido()
    real_add = store.add_unlock_slot
    calls = {"n": 0}

    def _fail_on_second(fingerprint: str, slot: object) -> int:
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("disk full")
        return real_add(fingerprint, slot)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "add_unlock_slot", _fail_on_second)

    with _pin() as pin, SecureBytes.from_bytes(b"emergency") as fallback, pytest.raises(RuntimeError):
        _service(store, gpg, fido).create_key_with_token(
            name="Alice",
            email="alice@example.org",
            algorithm=KeyAlgorithm.EDDSA,
            length=0,
            expiry="0",
            pin=pin,
            emergency_passphrase=fallback,
        )

    assert store.unlock_slots(FPR) == []


# ----------------------------------------------------------- existing key


def test_an_existing_key_is_bound_without_being_changed(store: MetadataStore) -> None:
    gpg, fido = _FakeGPG(), _FakeFido()
    service = _service(store, gpg, fido)

    with _pin() as pin, SecureBytes.from_bytes(b"my old passphrase") as existing:
        service.bind_existing_key(FPR, existing, pin=pin)

    # No key was generated and none deleted: the key itself was never touched.
    assert gpg.generated_passphrase is None
    assert gpg.deleted == []

    with _pin() as pin, service.unlock_with_token(FPR, pin=pin) as recovered:
        assert recovered.to_bytes() == b"my old passphrase"


def test_a_passphrase_that_does_not_open_the_key_is_not_enrolled(
    store: MetadataStore,
) -> None:
    """Otherwise the slot would faithfully return something GnuPG rejects."""
    gpg, fido = _FakeGPG(sign_fails=True), _FakeFido()

    with (
        _pin() as pin,
        SecureBytes.from_bytes(b"wrong") as wrong,
        pytest.raises(KeyUnlockError, match="does not open this key"),
    ):
        _service(store, gpg, fido).bind_existing_key(FPR, wrong, pin=pin)

    assert store.unlock_slots(FPR) == []


# ------------------------------------------------------------------ unlocking


def test_unlocking_a_key_with_no_token_says_so(store: MetadataStore) -> None:
    with _pin() as pin, pytest.raises(NoUnlockMethodError):
        _service(store, _FakeGPG(), _FakeFido()).unlock_with_token(OTHER_FPR, pin=pin)


def test_a_wrong_pin_stops_immediately_instead_of_trying_every_slot(
    store: MetadataStore,
) -> None:
    """Each retry burns one of the token's few PIN attempts, for no gain."""
    gpg, fido = _FakeGPG(), _FakeFido()
    service = _service(store, gpg, fido)
    with _pin() as pin, SecureBytes.from_bytes(b"pw") as existing:
        service.bind_existing_key(FPR, existing, pin=pin)

    fido.derive_calls = 0
    fido.derive_errors = [FidoPinError("rejected")]

    with _pin() as pin, pytest.raises(FidoPinError):
        service.unlock_with_token(FPR, pin=pin)

    assert fido.derive_calls == 1


def test_a_missed_touch_is_not_retried_either(store: MetadataStore) -> None:
    gpg, fido = _FakeGPG(), _FakeFido()
    service = _service(store, gpg, fido)
    with _pin() as pin, SecureBytes.from_bytes(b"pw") as existing:
        service.bind_existing_key(FPR, existing, pin=pin)

    fido.derive_errors = [FidoTouchError("not touched")]

    with _pin() as pin, pytest.raises(FidoTouchError):
        service.unlock_with_token(FPR, pin=pin)


def test_forgetting_a_key_removes_every_way_in(store: MetadataStore) -> None:
    gpg, fido = _FakeGPG(), _FakeFido()
    service = _service(store, gpg, fido)
    with _pin() as pin, SecureBytes.from_bytes(b"pw") as existing:
        service.bind_existing_key(FPR, existing, pin=pin)

    service.forget_key(FPR)

    assert not service.methods_for(FPR).is_managed


def test_an_unmanaged_key_reports_no_methods(store: MetadataStore) -> None:
    methods = _service(store, _FakeGPG(), _FakeFido()).methods_for(OTHER_FPR)

    assert not methods.is_managed
    assert not methods.has_token
    assert not methods.has_passphrase
