"""Thin adapter over the GnuPG command-line interface.

Hardened against the most common subprocess pitfalls (planv2.md §4.5, §5.6):

- `shell=False` is enforced by explicit `subprocess.Popen` argv lists; we
  additionally assert that none of the constructed argv elements contain the
  passphrase bytes.
- `--batch --pinentry-mode loopback` is mandatory so GPG never tries to spawn an
  external Pinentry, which would block our subprocess waiting for terminal input.
- `--homedir` is always set explicitly so we never touch the user's `~/.gnupg/`
  keyring.
- Passphrases are written as bytes to an app-owned pipe created with `os.pipe()`
  and passed to GPG via `--passphrase-fd`.
- Output translates GPG's status/stdout streams into our domain models; no
  third-party type leaks past this module.

Tests live in two places:
- `tests/unit/test_gpg_service_validation.py` covers validation, argv invariants
  and configuration without invoking GPG.
- `tests/integration/test_gpg_service.py` (marked `integration`) actually runs GPG
  in a temporary keyring.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo, TrustLevel
from gpg_meister.models.message import SignatureStatus
from gpg_meister.security.secure_bytes import SecureBytes, zero_mutable_buffer
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

_REQUIRED_GPG_ARGS: tuple[str, ...] = (
    "--batch",
    "--pinentry-mode",
    "loopback",
)

# Minimal environment allow-list for spawned GPG subprocesses. Anything not
# listed here (notably LD_PRELOAD / LD_LIBRARY_PATH / DYLD_INSERT_LIBRARIES /
# GNUPGHOME / GPG_AGENT_INFO / PINENTRY_USER_DATA) is dropped so that an
# attacker who can influence the parent environment cannot inject a dynamic
# library or alter GPG's behaviour out-of-band. `--homedir` is set explicitly
# elsewhere; GPG falls back to compiled defaults for anything else.
_GPG_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "LANGUAGE",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "LC_NUMERIC",
        "TZ",
        "TMPDIR",
        "TEMP",
        "TMP",
        # Display vars are kept off-list: with --batch --pinentry-mode loopback
        # GPG never spawns pinentry, so DISPLAY/WAYLAND_DISPLAY/XAUTHORITY are
        # not needed. Keeping them out also prevents a hijacked DISPLAY from
        # influencing any GPG helper that might consult it.
    }
)


def _clean_env() -> dict[str, str]:
    """Return a minimal environment for GPG subprocesses.

    Drops dynamic-linker variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`,
    `DYLD_INSERT_LIBRARIES`) and GPG-specific overrides that could subvert
    `--homedir` or the loopback pinentry policy.
    """
    return {k: v for k, v in os.environ.items() if k in _GPG_ENV_ALLOWLIST}


@dataclass(frozen=True)
class _GPGRun:
    """Result of a single GPG subprocess invocation.

    `status` carries only `[GNUPG:]` lines read from a dedicated status pipe;
    `stderr` carries only diagnostic text. They are never multiplexed.
    """

    args: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    status: bytes


@dataclass(frozen=True)
class GPGServiceConfig:
    binary_path: Path
    home_dir: Path
    timeout_seconds: int = 60
    trusted_sha256: str | None = None
    trusted_device: int | None = None
    trusted_inode: int | None = None


# GnuPG colon-format trust letters → our TrustLevel (doc/DETAILS).
_TRUST_MAP: dict[str, TrustLevel] = {
    "u": TrustLevel.ULTIMATE,
    "f": TrustLevel.FULL,
    "m": TrustLevel.MARGINAL,
    "n": TrustLevel.NEVER,
    "-": TrustLevel.UNKNOWN,
    "q": TrustLevel.UNKNOWN,
    "e": TrustLevel.UNKNOWN,
    "r": TrustLevel.NEVER,
}

# GnuPG numeric algorithm IDs → our enum (doc/DETAILS):
# 1=RSA, 17=DSA, 18=ECDH, 19=ECDSA, 22=EdDSA.
_ALGORITHM_MAP: dict[str, KeyAlgorithm] = {
    "1": KeyAlgorithm.RSA,
    "17": KeyAlgorithm.DSA,
    "18": KeyAlgorithm.ECDH,
    "19": KeyAlgorithm.ECDSA,
    "22": KeyAlgorithm.EDDSA,
}


def _trust_from_gpg(letter: str) -> TrustLevel:
    return _TRUST_MAP.get(letter, TrustLevel.UNKNOWN)


def _algorithm_from_gpg(numeric: str) -> KeyAlgorithm:
    """Map GnuPG's numeric algorithm id (`pub:1`, etc.) to our enum."""
    return _ALGORITHM_MAP.get(numeric, KeyAlgorithm.UNKNOWN)


def _to_key_info(entry: dict[str, Any]) -> KeyInfo:
    fingerprint = entry.get("fingerprint", "")
    uids_raw = entry.get("uids", [])
    user_ids = tuple(uid for uid in uids_raw if isinstance(uid, str))
    created = int(entry.get("date") or 0)
    expires_raw = entry.get("expires") or ""
    expires = int(expires_raw) if expires_raw and expires_raw.isdigit() else 0

    # Field 15 in colons format is the S/N of a token (smartcard).
    is_stub = bool(entry.get("token_sn"))

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
        is_stub=is_stub,
        trust=_trust_from_gpg(str(entry.get("trust", "-"))[:1] or "-"),
    )


def _decode_output(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _require_ok(proc: _GPGRun, message: str, *, ok: tuple[int, ...] = (0,)) -> None:
    """Raise ``GPGProcessError`` unless the run's return code is acceptable.

    Centralises the ``message: <truncated stderr>`` pattern so the truncation
    width and decoding stay identical across every call site. ``ok`` lists the
    return codes that count as success (delete operations also accept 2).
    """
    if proc.returncode not in ok:
        raise GPGProcessError(f"{message}: {_decode_output(proc.stderr)[:200]}")


def _hash_binary(path: Path) -> str | None:
    """SHA-256 of a file, or None if it cannot be read. Used for the cheap
    pre-invocation re-hash that detects an in-place binary rewrite."""
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _parse_colons_keys(data: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in _decode_output(data).splitlines():
        fields = raw_line.split(":")
        if not fields:
            continue
        rec_type = fields[0]
        if rec_type in {"pub", "sec"}:
            current = {
                "type": rec_type,
                "trust": fields[1] if len(fields) > 1 else "",
                "length": fields[2] if len(fields) > 2 else "",
                "algo": fields[3] if len(fields) > 3 else "",
                "date": fields[5] if len(fields) > 5 else "",
                "expires": fields[6] if len(fields) > 6 else "",
                "uids": [],
                "token_sn": fields[14] if len(fields) > 14 else "",
            }
            rows.append(current)
        elif rec_type == "fpr" and current is not None and len(fields) > 9:
            current.setdefault("fingerprint", fields[9])
        elif rec_type == "uid" and current is not None and len(fields) > 9:
            uid = fields[9]
            if uid:
                current.setdefault("uids", []).append(uid)
    return [row for row in rows if row.get("fingerprint")]


def _parse_status(stderr: bytes) -> list[list[str]]:
    records: list[list[str]] = []
    for line in _decode_output(stderr).splitlines():
        if not line.startswith("[GNUPG:] "):
            continue
        records.append(line.removeprefix("[GNUPG:] ").split())
    return records


# GnuPG emits exactly one of these per signature; the ones other than GOODSIG
# all mean "do not trust this signature as-is" even though gpg still exits 0 and
# (for the EXP*/REV* variants) still emits a companion VALIDSIG line.
_SIG_DOWNGRADE = {
    "REVKEYSIG": SignatureStatus.REVOKED_KEY,
    "EXPKEYSIG": SignatureStatus.EXPIRED_KEY,
    "EXPSIG": SignatureStatus.EXPIRED_SIG,
    "BADSIG": SignatureStatus.INVALID,
    "ERRSIG": SignatureStatus.ERROR,
}


def _evaluate_signature(
    records: Iterable[Sequence[str]],
) -> tuple[SignatureStatus, str | None, datetime | None]:
    """Derive ``(status, signer_fingerprint, signed_at)`` from gpg status records.

    Validity is taken from the status records, never the exit code. A signature
    is :data:`SignatureStatus.VALID` only when gpg reports ``GOODSIG`` *and*
    ``VALIDSIG`` and none of the revocation/expiry/error variants are present.
    Revoked- or expired-key signatures still produce a ``VALIDSIG`` line (so the
    fingerprint is recovered) but are downgraded so callers never treat them as
    trustworthy. The signer fingerprint is bound to the full-length ``VALIDSIG``
    fingerprint rather than the short key id from ``GOODSIG``/``BADSIG``.
    """
    has_goodsig = False
    has_validsig = False
    downgrade: SignatureStatus | None = None
    signer_fp: str | None = None
    signed_at: datetime | None = None

    for record in records:
        if not record:
            continue
        tag = record[0]
        if tag == "GOODSIG":
            has_goodsig = True
        elif tag == "VALIDSIG" and len(record) > 1:
            has_validsig = True
            signer_fp = record[1]
            for token in record[2:]:
                if token.isdigit():
                    with contextlib.suppress(ValueError, OSError, OverflowError):
                        signed_at = datetime.fromtimestamp(float(token), tz=UTC)
                    break
        elif tag in _SIG_DOWNGRADE:
            # Worst observed problem wins (a later BADSIG must not be masked).
            downgrade = _SIG_DOWNGRADE[tag]

    if downgrade is not None:
        return downgrade, signer_fp, signed_at
    if has_goodsig and has_validsig:
        return SignatureStatus.VALID, signer_fp, signed_at
    if has_goodsig or has_validsig:
        # A lone GOODSIG/VALIDSIG without its companion is anomalous; refuse to
        # assert validity rather than fail open.
        return SignatureStatus.ERROR, signer_fp, signed_at
    return SignatureStatus.NONE, None, None


def _write_all(fd: int, data: bytes | bytearray | memoryview) -> None:
    view = memoryview(data)
    try:
        offset = 0
        while offset < len(view):
            written = os.write(fd, view[offset:])
            if written <= 0:
                raise OSError("short write to passphrase pipe")
            offset += written
    finally:
        view.release()


class GPGService:
    """Encapsulates a configured GnuPG home and binary.

    Construct once per resolved GPG home; share the instance across the application.
    """

    def __init__(self, config: GPGServiceConfig) -> None:
        if not config.binary_path.exists():
            raise GPGServiceError(f"GPG binary does not exist: {config.binary_path}")
        # The hash observed this session is pinned regardless of whitelist status,
        # so an in-place rewrite of the same inode (which the device/inode check
        # cannot see) is caught before invocation. This is a *session* pin, not a
        # persisted one, so legitimate cross-run binary upgrades are unaffected.
        self._binary_sha256: str = self._revalidate_binary(config)
        # Capture device/inode immediately after hash-based validation so that
        # _assert_binary_not_swapped() can perform a cheap pre-invocation check.
        try:
            _st = config.binary_path.stat()
            self._binary_dev: int | None = _st.st_dev
            self._binary_ino: int | None = _st.st_ino
        except OSError:
            self._binary_dev = None
            self._binary_ino = None
        # Only chmod the home directory when we are creating it. If it already
        # exists (e.g. the user's real ~/.gnupg) we must not mutate its permissions,
        # because that would alter existing system configuration (vuln 2.1).
        if config.home_dir.exists():
            if not config.home_dir.is_dir():
                raise GPGServiceError(f"GPG home exists but is not a directory: {config.home_dir}")
        else:
            ensure_dir(config.home_dir, mode=0o700)

        self._config = config

    def _assert_binary_not_swapped(self) -> None:
        """Pre-invocation check: verify device/inode *and* content hash match startup.

        The device/inode check is cheap but blind to an in-place rewrite of the
        same inode; re-hashing closes that gap so a binary modified mid-session
        is caught before it is executed.
        """
        if self._binary_dev is None and self._binary_ino is None:
            return
        try:
            st = self._config.binary_path.stat()
        except OSError as exc:
            raise GPGServiceError(f"GPG binary inaccessible before invocation: {exc}") from exc
        if self._binary_dev is not None and st.st_dev != self._binary_dev:
            raise GPGServiceError("GPG binary device changed since startup — possible substitution")
        if self._binary_ino is not None and st.st_ino != self._binary_ino:
            raise GPGServiceError("GPG binary inode changed since startup — possible substitution")
        if self._binary_sha256:
            current = _hash_binary(self._config.binary_path)
            if current is not None and current.lower() != self._binary_sha256.lower():
                raise GPGServiceError(
                    "GPG binary contents changed since startup — possible substitution"
                )

    def _revalidate_binary(self, config: GPGServiceConfig) -> str:
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
        return detected.sha256

    @property
    def config(self) -> GPGServiceConfig:
        return self._config

    def _base_cmd(self) -> list[str]:
        return [
            str(self._config.binary_path),
            "--homedir",
            str(self._config.home_dir),
            *_REQUIRED_GPG_ARGS,
        ]

    def _run_gpg(
        self,
        args: Sequence[str],
        *,
        input_data: bytes | bytearray | memoryview | None = None,
        passphrase: SecureBytes | bytes | None = None,
        status_fd: bool = False,
    ) -> _GPGRun:
        """Run GPG with optional byte-only passphrase pipe handling.

        When `status_fd=True`, GPG's `[GNUPG:]` status lines are routed to a
        dedicated, app-owned pipe rather than multiplexed onto stderr. This
        prevents an attacker-controlled diagnostic line on stderr from being
        mistaken for a real status record by `_parse_status`.
        """
        self._assert_binary_not_swapped()
        pass_read: int | None = None
        pass_write: int | None = None
        status_read: int | None = None
        status_write: int | None = None
        pass_bytes = bytearray()
        pass_writer: threading.Thread | None = None
        status_reader: threading.Thread | None = None
        status_buf = bytearray()
        cmd = self._base_cmd()
        if status_fd:
            status_read, status_write = os.pipe()
            os.set_inheritable(status_write, True)
            cmd.extend(["--status-fd", str(status_write)])
        if passphrase is not None:
            pass_bytes = (
                bytearray(passphrase.view())
                if isinstance(passphrase, SecureBytes)
                else bytearray(passphrase)
            )
            # Reject framing bytes (NUL terminates many C string paths inside
            # pinentry helpers; CR/LF would prematurely close the
            # `--passphrase-fd` line) plus other ASCII control characters that
            # have no legitimate place in a passphrase.
            for _b in (0x00, 0x0A, 0x0D):
                if _b in pass_bytes:
                    raise GPGValidationError(
                        "passphrase must not contain NUL or newline characters"
                    )
            reject_passphrase_in_argv(cmd, pass_bytes)
            pass_read, pass_write = os.pipe()
            os.set_inheritable(pass_read, True)
            cmd.extend(["--passphrase-fd", str(pass_read)])
        cmd.extend(args)
        reject_passphrase_in_argv(cmd, pass_bytes)
        inherited_fds: tuple[int, ...] = tuple(
            fd for fd in (pass_read, status_write) if fd is not None
        )
        try:
            proc = subprocess.Popen(  # noqa: S603
                cmd,
                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=inherited_fds,
                env=_clean_env(),
                close_fds=True,
            )
            if pass_read is not None:
                os.close(pass_read)
                pass_read = None
            if status_write is not None:
                os.close(status_write)
                status_write = None
            if status_read is not None:
                sfd = status_read
                status_read = None

                def _drain_status() -> None:
                    try:
                        while True:
                            chunk = os.read(sfd, 4096)
                            if not chunk:
                                return
                            # Bound the buffer so a runaway GPG can't OOM us.
                            if len(status_buf) + len(chunk) > 1 * 1024 * 1024:
                                return
                            status_buf.extend(chunk)
                    except OSError:
                        return
                    finally:
                        with contextlib.suppress(OSError):
                            os.close(sfd)

                status_reader = threading.Thread(target=_drain_status, daemon=True)
                status_reader.start()
            if pass_write is not None:
                fd = pass_write
                pass_write = None

                def _write_passphrase() -> None:
                    nonlocal pass_bytes
                    try:
                        _write_all(fd, memoryview(pass_bytes))
                        _write_all(fd, b"\n")
                    except OSError:
                        pass
                    finally:
                        with contextlib.suppress(OSError):
                            os.close(fd)
                        if pass_bytes:
                            zero_mutable_buffer(pass_bytes)
                            pass_bytes = bytearray()

                pass_writer = threading.Thread(target=_write_passphrase, daemon=True)
                pass_writer.start()
            try:
                stdout, stderr = proc.communicate(
                    input=cast(bytes | None, input_data),
                    timeout=self._config.timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                raise GPGProcessError(
                    f"GPG operation timed out after {self._config.timeout_seconds}s"
                ) from None
            if status_reader is not None:
                status_reader.join(timeout=1.0)
            return _GPGRun(
                args=tuple(cmd),
                returncode=proc.returncode,
                stdout=stdout or b"",
                stderr=stderr or b"",
                status=bytes(status_buf),
            )
        finally:
            if pass_read is not None:
                with contextlib.suppress(OSError):
                    os.close(pass_read)
            if pass_write is not None:
                with contextlib.suppress(OSError):
                    os.close(pass_write)
            if status_read is not None:
                with contextlib.suppress(OSError):
                    os.close(status_read)
            if status_write is not None:
                with contextlib.suppress(OSError):
                    os.close(status_write)
            if pass_writer is not None:
                pass_writer.join(timeout=1.0)
            if status_reader is not None and status_reader.is_alive():
                status_reader.join(timeout=1.0)
            if pass_bytes:
                zero_mutable_buffer(pass_bytes)

    # ------------------------------------------------------------------ inventory

    def _secret_fingerprints(self) -> set[str]:
        proc = self._run_gpg(["--with-colons", "--fingerprint", "--list-secret-keys"])
        _require_ok(proc, "failed to list secret keys")
        rows: Iterable[dict[str, Any]] = _parse_colons_keys(proc.stdout)
        return {str(r.get("fingerprint", "")).upper() for r in rows if r.get("fingerprint")}

    def list_keys(self, *, secret: bool = False) -> list[KeyInfo]:
        args = ["--with-colons", "--fingerprint", "--list-secret-keys" if secret else "--list-keys"]
        proc = self._run_gpg(args)
        _require_ok(proc, f"failed to list {'secret ' if secret else ''}keys")
        rows = _parse_colons_keys(proc.stdout)
        # A secret listing implies every row has a private key; for a public
        # listing we cross-reference the secret fingerprints once.
        secret_fps: set[str] = set() if secret else self._secret_fingerprints()
        infos: list[KeyInfo] = []
        for row in rows:
            info = _to_key_info(row)
            if secret or info.fingerprint in secret_fps:
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

        pass_view = passphrase.view()
        if 0x0A in pass_view or 0x0D in pass_view:
            raise GPGValidationError("passphrase must not contain newline characters")

        if algorithm is KeyAlgorithm.EDDSA:
            quick_args = ["--quick-generate-key", f"{name} <{email}>", "future-default", "default", expiry]
        elif algorithm is KeyAlgorithm.RSA:
            quick_args = ["--quick-generate-key", f"{name} <{email}>", f"rsa{length}", "default", expiry]
        else:
            raise GPGValidationError(f"key generation not supported for {algorithm}")

        proc = self._run_gpg(
            ["--yes", *quick_args],
            passphrase=passphrase,
            status_fd=True,
        )
        _require_ok(proc, "GPG key generation failed")
        fp = ""
        for record in _parse_status(proc.status):
            if record and record[0] == "KEY_CREATED" and len(record) >= 3:
                fp = record[2]
        if not fp:
            matches = [
                k.fingerprint
                for k in self.list_keys(secret=True)
                if f"{name} <{email}>" in k.user_ids
            ]
            fp = matches[-1] if matches else ""
        if not fp:
            raise GPGProcessError("GPG did not return a fingerprint")
        return validate_fingerprint(fp)

    # --------------------------------------------------------------------- export

    def export_public_key(self, fingerprint: str) -> str:
        fp = validate_fingerprint(fingerprint)
        proc = self._run_gpg(["--armor", "--export", fp])
        armored = _decode_output(proc.stdout)
        if not armored:
            msg = f"no public key for {fp}"
            if proc.stderr:
                msg += f": {_decode_output(proc.stderr)[:200]}"
            raise GPGKeyNotFoundError(msg)
        return armored

    def export_private_key(self, fingerprint: str, passphrase: SecureBytes) -> str:
        fp = validate_fingerprint(fingerprint)
        proc = self._run_gpg(
            ["--armor", "--export-secret-keys", fp],
            passphrase=passphrase,
            status_fd=True,
        )
        armored = _decode_output(proc.stdout)
        if not armored:
            err = _decode_output(proc.stderr)
            if "bad passphrase" in err.lower() or "bad_passphrase" in err.lower():
                raise GPGPassphraseError("private key export failed: incorrect passphrase")

            msg = f"private key export failed for {fp}"
            if err:
                msg += f": {err[:200]}"
            else:
                msg += " — key missing or passphrase incorrect"
            raise GPGPassphraseError(msg)
        return armored

    # --------------------------------------------------------------------- import

    def import_key(self, armored: str | bytes | bytearray | memoryview) -> list[str]:
        input_data = armored.encode("utf-8") if isinstance(armored, str) else armored
        proc = self._run_gpg(["--import"], input_data=input_data, status_fd=True)
        fingerprints = [
            record[2]
            for record in _parse_status(proc.status)
            if record and record[0] == "IMPORT_OK" and len(record) > 2
        ]
        if not fingerprints:
            raise GPGProcessError(
                f"key import returned no fingerprints: {_decode_output(proc.stderr)[:200]}"
            )
        return [validate_fingerprint(fp) for fp in fingerprints]

    def scan_keys(self, armored: str) -> list[dict[str, Any]]:
        proc = self._run_gpg(
            ["--with-colons", "--fingerprint", "--show-keys"],
            input_data=armored.encode("utf-8"),
        )
        _require_ok(proc, "key scan failed")
        return _parse_colons_keys(proc.stdout)

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
            # Use --delete-secret-and-public-key to delete both in a single GPG
            # invocation. This avoids the race where a crash between two separate
            # calls would leave an orphan public key with no private counterpart.
            proc = self._run_gpg(
                ["--yes", "--delete-secret-and-public-key", fp],
                passphrase=passphrase,
            )
            _require_ok(proc, f"failed to delete key {fp}", ok=(0, 2))
        else:
            proc = self._run_gpg(["--yes", "--delete-key", fp])
            _require_ok(proc, f"failed to delete public key {fp}", ok=(0, 2))
        try:
            self.find_key(fp)
        except GPGKeyNotFoundError:
            return
        raise GPGProcessError(f"failed to delete key {fp}: key is still present")

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
        args = ["--armor"]
        if always_trust:
            args.extend(["--trust-model", "always"])
        args.append("--encrypt")
        for recipient in recipients:
            args.extend(["--recipient", recipient])
        if signer:
            if passphrase is None:
                raise GPGValidationError("signing requires a passphrase")
            args.extend(["--sign", "--local-user", signer])
        proc = self._run_gpg(
            args,
            input_data=plaintext,
            passphrase=passphrase if signer else None,
            status_fd=True,
        )
        _require_ok(proc, "encryption failed")
        return _decode_output(proc.stdout)

    def decrypt(
        self,
        ciphertext: bytes,
        *,
        passphrase: SecureBytes | None = None,
    ) -> tuple[bytes, str | None, SignatureStatus]:
        """Return (plaintext, signer_fingerprint_if_any, signature_status).

        ``signature_status`` is derived from the gpg status records, so a
        signature from a revoked or expired key is reported as such instead of
        being treated as valid (gpg exits 0 in those cases).
        """
        proc = self._run_gpg(
            ["--decrypt"],
            input_data=ciphertext,
            passphrase=passphrase,
            status_fd=True,
        )
        status_text = _decode_output(proc.status)
        stderr_text = _decode_output(proc.stderr)
        if proc.returncode != 0:
            combined = (status_text + "\n" + stderr_text).lower()
            detail = (stderr_text or status_text)[:200]
            if "bad_passphrase" in combined or "bad passphrase" in combined or "no secret key" in combined:
                raise GPGPassphraseError(f"decryption failed: {detail}")
            raise GPGProcessError(f"decryption failed: {detail}")
        status, signer, _ = _evaluate_signature(_parse_status(proc.status))
        return bytes(proc.stdout or b""), signer, status

    def sign(
        self,
        data: bytes,
        *,
        fingerprint: str,
        passphrase: SecureBytes,
        detached: bool = True,
    ) -> str:
        fp = validate_fingerprint(fingerprint)
        args = ["--armor", "--local-user", fp]
        args.append("--detach-sign" if detached else "--clearsign")
        proc = self._run_gpg(
            args,
            input_data=data,
            passphrase=passphrase,
            status_fd=True,
        )
        if proc.returncode != 0 or not proc.stdout:
            raise GPGProcessError(f"signing failed: {_decode_output(proc.stderr)[:200]}")
        return _decode_output(proc.stdout)

    def verify(
        self,
        data: bytes,
        *,
        detached_signature: bytes | None = None,
    ) -> tuple[SignatureStatus, str | None, datetime | None]:
        """Return (signature_status, signer_fingerprint, signed_at).

        Validity is derived from the gpg status records, not the exit code, so
        signatures from revoked or expired keys (which gpg still exits 0 for)
        are reported as such rather than as valid.
        """
        if detached_signature is not None:
            # We use a named temporary file in the GPG home directory (which is
            # 0700) to avoid leaving detached data in global /tmp.
            with tempfile.NamedTemporaryFile(
                suffix=".asc",
                dir=self._config.home_dir,
                delete=False,
            ) as tmp:
                tmp.write(detached_signature)
                sig_path = tmp.name
            with tempfile.NamedTemporaryFile(
                suffix=".data",
                dir=self._config.home_dir,
                delete=False,
            ) as tmp_data:
                tmp_data.write(data)
                data_path = tmp_data.name
            try:
                proc = self._run_gpg(["--verify", sig_path, data_path], status_fd=True)
            finally:
                with contextlib.suppress(OSError):
                    os.unlink(sig_path)
                with contextlib.suppress(OSError):
                    os.unlink(data_path)
        else:
            proc = self._run_gpg(["--verify"], input_data=data, status_fd=True)

        status, fp, signed_at = _evaluate_signature(_parse_status(proc.status))
        return status, fp, signed_at

    # ---------------------------------------------------------------------- meta

    def version(self) -> tuple[int, ...]:
        """Return the GPG binary's version as a tuple, e.g. (2, 4, 4)."""
        self._assert_binary_not_swapped()
        proc = subprocess.run(  # noqa: S603
            [str(self._config.binary_path), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=self._config.timeout_seconds,
            env=_clean_env(),
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
