"""Thin adapter over `python-gnupg`.

Hardened against the most common subprocess pitfalls (planv2.md §4.5, §5.6):

- `shell=False` is enforced by `python-gnupg`; we additionally assert that none of
  the constructed argv elements contain the passphrase bytes.
- `--batch --pinentry-mode loopback` is mandatory so GPG never tries to spawn an
  external Pinentry, which would block our subprocess waiting for terminal input.
- `--homedir` is always set explicitly so we never touch the user's `~/.gnupg/`
  keyring.
- Passphrases are passed through `python-gnupg`'s `passphrase=` keyword which uses
  `--passphrase-fd` internally (verified by the `test_passphrase_not_in_argv` test).
- Output translates `gnupg.Result` objects into our domain models; no third-party
  type leaks past this module.

Tests live in two places:
- `tests/unit/test_gpg_service_validation.py` covers validation, argv invariants
  and configuration without invoking GPG.
- `tests/integration/test_gpg_service.py` (marked `integration`) actually runs GPG
  in a temporary keyring.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import gnupg

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo, TrustLevel
from gpg_meister.security.secure_bytes import SecureBytes
from gpg_meister.services.errors import (
    GPGKeyNotFoundError,
    GPGPassphraseError,
    GPGProcessError,
    GPGServiceError,
    GPGValidationError,
)
from gpg_meister.services.validation import (
    reject_passphrase_in_argv,
    validate_email,
    validate_expiry,
    validate_fingerprint,
    validate_key_algorithm_and_length,
    validate_user_name,
)
from gpg_meister.storage.permissions import ensure_dir

# python-gnupg's `gpg.encrypt`/`gpg.sign`/etc. methods accept `passphrase=` as a
# Python string. Internally they write it to a pipe linked to `--passphrase-fd`,
# so the value never appears in argv. To guarantee that under future versions we
# also feed our own subprocess assertions.
_REQUIRED_GPG_ARGS: tuple[str, ...] = (
    "--batch",
    "--pinentry-mode",
    "loopback",
)


@dataclass(frozen=True)
class GPGServiceConfig:
    binary_path: Path
    home_dir: Path
    timeout_seconds: int = 60
    trusted_sha256: str | None = None
    trusted_device: int | None = None
    trusted_inode: int | None = None


def _trust_from_gpg(letter: str) -> TrustLevel:
    return {
        "u": TrustLevel.ULTIMATE,
        "f": TrustLevel.FULL,
        "m": TrustLevel.MARGINAL,
        "n": TrustLevel.NEVER,
        "-": TrustLevel.UNKNOWN,
        "q": TrustLevel.UNKNOWN,
        "e": TrustLevel.UNKNOWN,
        "r": TrustLevel.NEVER,
    }.get(letter, TrustLevel.UNKNOWN)


def _algorithm_from_gpg(numeric: str) -> KeyAlgorithm:
    """Map GnuPG's numeric algorithm id (`pub:1`, etc.) to our enum."""
    # GnuPG algorithm IDs per doc/DETAILS:
    # 1=RSA, 17=DSA, 18=ECDH, 19=ECDSA, 22=EdDSA
    return {
        "1": KeyAlgorithm.RSA,
        "17": KeyAlgorithm.DSA,
        "18": KeyAlgorithm.ECDH,
        "19": KeyAlgorithm.ECDSA,
        "22": KeyAlgorithm.EDDSA,
    }.get(numeric, KeyAlgorithm.UNKNOWN)


def _to_key_info(entry: dict[str, Any]) -> KeyInfo:
    fingerprint = entry.get("fingerprint", "")
    uids_raw = entry.get("uids", [])
    user_ids = tuple(uid for uid in uids_raw if isinstance(uid, str))
    created = int(entry.get("date") or 0)
    expires_raw = entry.get("expires") or ""
    expires = int(expires_raw) if expires_raw and expires_raw.isdigit() else 0
    return KeyInfo(
        fingerprint=fingerprint,
        user_ids=user_ids,
        algorithm=_algorithm_from_gpg(str(entry.get("algo", "1"))),
        raw_algorithm_id=str(entry.get("algo", "")),
        length=int(entry.get("length") or 0) or 2048,
        created_at=datetime.fromtimestamp(created, tz=UTC) if created else datetime.now(UTC),
        expires_at=datetime.fromtimestamp(expires, tz=UTC) if expires else None,
        is_revoked=str(entry.get("trust", "")) == "r",
        has_private_key="sec" in entry.get("type", "") if isinstance(entry.get("type"), str) else False,
        trust=_trust_from_gpg(str(entry.get("trust", "-"))[:1] or "-"),
    )


class GPGService:
    """Encapsulates a configured `gnupg.GPG` handle.

    Construct once per resolved GPG home; share the instance across the application.
    """

    def __init__(self, config: GPGServiceConfig) -> None:
        if not config.binary_path.exists():
            raise GPGServiceError(f"GPG binary does not exist: {config.binary_path}")
        self._revalidate_binary(config)
        ensure_dir(config.home_dir, mode=0o700)

        self._config = config
        self._gpg = gnupg.GPG(
            gpgbinary=str(config.binary_path),
            gnupghome=str(config.home_dir),
            use_agent=False,
            options=list(_REQUIRED_GPG_ARGS),
        )
        # Verify python-gnupg actually applied our required args.
        applied = list(self._gpg.options or ())
        for needed in _REQUIRED_GPG_ARGS:
            if needed not in applied:
                raise GPGServiceError(
                    f"python-gnupg did not apply required option {needed!r}"
                )

    def _revalidate_binary(self, config: GPGServiceConfig) -> None:
        from gpg_meister.startup.gpg_detector import detect

        detected = detect(
            user_override_path=str(config.binary_path),
            trusted_hash=config.trusted_sha256,
            trusted_path=str(config.binary_path) if config.trusted_sha256 else None,
            trusted_device=config.trusted_device,
            trusted_inode=config.trusted_inode,
        )
        if detected.path != config.binary_path.resolve():
            raise GPGServiceError("GPG binary path changed before service startup")
        if config.trusted_sha256 and detected.sha256.lower() != config.trusted_sha256.lower():
            raise GPGServiceError("GPG binary hash changed before service startup")
        if config.trusted_device is not None and detected.device != config.trusted_device:
            raise GPGServiceError("GPG binary device changed before service startup")
        if config.trusted_inode is not None and detected.inode != config.trusted_inode:
            raise GPGServiceError("GPG binary inode changed before service startup")

    @property
    def config(self) -> GPGServiceConfig:
        return self._config

    # ------------------------------------------------------------------ inventory

    def _secret_fingerprints(self) -> set[str]:
        rows: Iterable[dict[str, Any]] = self._gpg.list_keys(secret=True)
        return {str(r.get("fingerprint", "")).upper() for r in rows if r.get("fingerprint")}

    def list_keys(self, *, secret: bool = False) -> list[KeyInfo]:
        rows: Iterable[dict[str, Any]] = self._gpg.list_keys(secret=secret)
        infos: list[KeyInfo] = []
        if secret:
            # All rows from a secret listing already have private keys.
            for row in rows:
                info = _to_key_info(row)
                infos.append(info.model_copy(update={"has_private_key": True}))
        else:
            secret_fps = self._secret_fingerprints()
            for row in rows:
                info = _to_key_info(row)
                if info.fingerprint in secret_fps:
                    info = info.model_copy(update={"has_private_key": True})
                infos.append(info)
        return infos

    def find_key(self, fingerprint: str) -> KeyInfo:
        fp = validate_fingerprint(fingerprint)
        for key in self.list_keys(secret=False):
            if key.fingerprint == fp:
                return key
        raise GPGKeyNotFoundError(f"key {fp} not found in keyring")

    # ----------------------------------------------------------------- generation

    def generate_key(
        self,
        *,
        name: str,
        email: str,
        algorithm: KeyAlgorithm,
        length: int,
        expiry: str,
        passphrase: SecureBytes,
    ) -> str:
        """Create a new key pair. Returns the fingerprint."""
        name = validate_user_name(name)
        email = validate_email(email)
        validate_key_algorithm_and_length(algorithm, length)
        validate_expiry(expiry)

        pass_bytes = bytes(passphrase.view())
        reject_passphrase_in_argv(list(self._gpg.options or ()), pass_bytes)

        params: dict[str, Any]
        if algorithm is KeyAlgorithm.EDDSA:
            params = {
                "name_real": name,
                "name_email": email,
                "key_type": "EDDSA",
                "key_curve": "ed25519",
                "subkey_type": "ECDH",
                "subkey_curve": "cv25519",
                "expire_date": expiry,
                "passphrase": pass_bytes.decode("utf-8"),
            }
        elif algorithm is KeyAlgorithm.RSA:
            params = {
                "name_real": name,
                "name_email": email,
                "key_type": "RSA",
                "key_length": length,
                "subkey_type": "RSA",
                "subkey_length": length,
                "expire_date": expiry,
                "passphrase": pass_bytes.decode("utf-8"),
            }
        else:
            raise GPGValidationError(f"key generation not supported for {algorithm}")

        gen_input = self._gpg.gen_key_input(**params)
        result = self._gpg.gen_key(gen_input)
        fp = str(getattr(result, "fingerprint", "") or "")
        if not fp:
            raise GPGProcessError(
                f"GPG did not return a fingerprint: {getattr(result, 'stderr', '')[:200]}"
            )
        return validate_fingerprint(fp)

    # --------------------------------------------------------------------- export

    def export_public_key(self, fingerprint: str) -> str:
        fp = validate_fingerprint(fingerprint)
        armored = self._gpg.export_keys(fp, secret=False, armor=True)
        if not armored:
            raise GPGKeyNotFoundError(f"no public key for {fp}")
        return str(armored)

    def export_private_key(self, fingerprint: str, passphrase: SecureBytes) -> str:
        fp = validate_fingerprint(fingerprint)
        pass_bytes = bytes(passphrase.view())
        reject_passphrase_in_argv(list(self._gpg.options or ()), pass_bytes)
        armored = self._gpg.export_keys(
            fp,
            secret=True,
            armor=True,
            passphrase=pass_bytes.decode("utf-8"),
            expect_passphrase=True,
        )
        if not armored:
            raise GPGPassphraseError(
                "private key export failed — passphrase incorrect or key missing"
            )
        return str(armored)

    # --------------------------------------------------------------------- import

    def import_key(self, armored: str) -> list[str]:
        result = self._gpg.import_keys(armored)
        fingerprints = [str(fp) for fp in getattr(result, "fingerprints", []) if fp]
        if not fingerprints:
            raise GPGProcessError(
                f"key import returned no fingerprints: {getattr(result, 'stderr', '')[:200]}"
            )
        return [validate_fingerprint(fp) for fp in fingerprints]

    # -------------------------------------------------------------------- delete

    def delete_key(
        self,
        fingerprint: str,
        *,
        including_secret: bool = False,
        passphrase: SecureBytes | None = None,
    ) -> None:
        fp = validate_fingerprint(fingerprint)
        if including_secret:
            pass_bytes = bytes(passphrase.view()) if passphrase else b""
            reject_passphrase_in_argv(list(self._gpg.options or ()), pass_bytes)
            # Use --delete-secret-and-public-key to delete both in a single GPG
            # invocation. This avoids the race where a crash between two separate
            # calls would leave an orphan public key with no private counterpart.
            cmd = [
                str(self._config.binary_path),
                "--homedir", str(self._config.home_dir),
                "--batch",
                "--yes",
                "--pinentry-mode", "loopback",
                "--delete-secret-and-public-key",
                fp,
            ]
            proc = subprocess.run(  # noqa: S603
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
            )
            if proc.returncode not in (0, 2):
                raise GPGProcessError(
                    f"failed to delete key {fp}: {proc.stderr[:200]}"
                )
        else:
            pub_result = self._gpg.delete_keys(fp, secret=False)
            if str(pub_result) not in ("ok", "No such key"):
                raise GPGProcessError(f"failed to delete public key {fp}: {pub_result}")

    # ------------------------------------------------------------------ messages

    def encrypt(
        self,
        plaintext: bytes,
        *,
        recipient_fingerprints: Sequence[str],
        sign_with: str | None = None,
        passphrase: SecureBytes | None = None,
        always_trust: bool = False,
    ) -> str:
        recipients = [validate_fingerprint(fp) for fp in recipient_fingerprints]
        signer = validate_fingerprint(sign_with) if sign_with else None
        kwargs: dict[str, Any] = {
            "recipients": recipients,
            "armor": True,
            "always_trust": always_trust,
        }
        if signer:
            kwargs["sign"] = signer
            if passphrase is None:
                raise GPGValidationError("signing requires a passphrase")
            pass_bytes = bytes(passphrase.view())
            reject_passphrase_in_argv(list(self._gpg.options or ()), pass_bytes)
            kwargs["passphrase"] = pass_bytes.decode("utf-8")
        result = self._gpg.encrypt(plaintext, **kwargs)
        if not result.ok:
            raise GPGProcessError(f"encryption failed: {result.status}")
        return str(result)

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        passphrase: SecureBytes | None = None,
    ) -> tuple[bytes, str | None, bool]:
        """Return (plaintext, signer_fingerprint_if_any, signature_valid)."""
        kwargs: dict[str, Any] = {}
        if passphrase is not None:
            pass_bytes = bytes(passphrase.view())
            reject_passphrase_in_argv(list(self._gpg.options or ()), pass_bytes)
            kwargs["passphrase"] = pass_bytes.decode("utf-8")
        result = self._gpg.decrypt(ciphertext, **kwargs)
        if not result.ok:
            if str(result.status or "").lower() in ("bad passphrase", "no secret key"):
                raise GPGPassphraseError(f"decryption failed: {result.status}")
            raise GPGProcessError(f"decryption failed: {result.status}")
        signer = str(result.fingerprint or "") or None
        valid = bool(result.valid) if signer else False
        return bytes(result.data or b""), signer, valid

    def sign(
        self,
        data: bytes,
        *,
        fingerprint: str,
        passphrase: SecureBytes,
        detached: bool = True,
    ) -> str:
        fp = validate_fingerprint(fingerprint)
        pass_bytes = bytes(passphrase.view())
        reject_passphrase_in_argv(list(self._gpg.options or ()), pass_bytes)
        result = self._gpg.sign(
            data,
            keyid=fp,
            passphrase=pass_bytes.decode("utf-8"),
            detach=detached,
            clearsign=not detached,
        )
        if not str(result):
            raise GPGProcessError(f"signing failed: {result.status}")
        return str(result)

    def verify(
        self,
        data: bytes,
        *,
        detached_signature: bytes | None = None,
    ) -> tuple[bool, str | None, datetime | None]:
        """Return (valid, signer_fingerprint, signed_at)."""
        if detached_signature is not None:
            with tempfile.NamedTemporaryFile(
                suffix=".asc",
                dir=tempfile.gettempdir(),
                delete=False,
            ) as tmp:
                tmp.write(detached_signature)
                sig_path = tmp.name
            try:
                result = self._gpg.verify_data(sig_path, data)
            finally:
                os.unlink(sig_path)
        else:
            result = self._gpg.verify(data)
        valid = bool(result.valid)
        fp = str(result.fingerprint or "") or None
        signed_at: datetime | None = None
        if result.timestamp:
            with contextlib.suppress(ValueError, OSError):
                signed_at = datetime.fromtimestamp(float(str(result.timestamp)), tz=UTC)
        return valid, fp, signed_at

    # ---------------------------------------------------------------------- meta

    def version(self) -> tuple[int, ...]:
        """Return the GPG binary's version as a tuple, e.g. (2, 4, 4)."""
        proc = subprocess.run(  # noqa: S603
            [str(self._config.binary_path), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=self._config.timeout_seconds,
        )
        first_line = (proc.stdout or "").splitlines()[0] if proc.stdout else ""
        parts = first_line.strip().split(" ")
        for token in parts:
            if token and token[0].isdigit() and "." in token:
                try:
                    return tuple(int(x) for x in token.split("."))
                except ValueError:
                    continue
        raise GPGProcessError(f"could not parse GPG version from: {first_line!r}")


def make_isolated_service(binary_path: Path, *, prefix: str = "gpg-meister-") -> GPGService:
    """Build a `GPGService` rooted in a fresh temporary directory.

    Useful for tests and the first-launch import wizard. The caller is responsible
    for cleaning the temporary directory.
    """
    home = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        return GPGService(GPGServiceConfig(binary_path=binary_path, home_dir=home))
    except Exception:
        shutil.rmtree(home, ignore_errors=True)
        raise
