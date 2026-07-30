"""Thin adapter over the GnuPG command-line interface.

Hardened against the most common subprocess pitfalls (planv2.md §4.5, §5.6):

- `shell=False` is enforced by explicit `subprocess.Popen` argv lists; we
  additionally assert that none of the constructed argv elements contain the
  passphrase bytes.
- `--batch --pinentry-mode loopback` is mandatory so GPG never tries to spawn an
  external Pinentry, which would block our subprocess waiting for terminal input.
  Smartcard PINs travel the same path: with loopback pinentry, gpg-agent asks us
  for the card PIN and it is answered from `--passphrase-fd`, so a YubiKey PIN
  never touches an external process either.
  The one exception is `run_prompt_script`, which drives GnuPG's interactive
  editors (`--card-edit`, `--edit-key`) — GnuPG refuses those under `--batch`.
  It keeps loopback pinentry (so still no external Pinentry) and answers every
  prompt from an app-owned `--command-fd` pipe; see that method for the rules
  that keep an unscripted prompt from being answered by accident.
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
from gpg_meister.services.card_scripts import PromptScript
from gpg_meister.services.errors import (
    GPGCardError,
    GPGCardPinError,
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


# Field 15 of a `sec`/`ssb` record (doc/DETAILS) is overloaded: "+" means the
# secret key is stored on this computer, "#" means it is not available here
# (offline primary or an unlearned stub), and anything else is the serial number
# of the token holding it.
_SECRET_AVAILABLE = "+"  # noqa: S105 - a GnuPG status marker, not a credential
_SECRET_UNAVAILABLE = "#"  # noqa: S105 - a GnuPG status marker, not a credential


def _token_state(raw: str) -> tuple[str, bool]:
    """Split field 15 into ``(card_serial, is_stub)``."""
    value = raw.strip()
    if not value or value == _SECRET_AVAILABLE:
        return "", False
    if value == _SECRET_UNAVAILABLE:
        return "", True
    return value, True


def _to_key_info(entry: dict[str, Any]) -> KeyInfo:
    fingerprint = entry.get("fingerprint", "")
    uids_raw = entry.get("uids", [])
    user_ids = tuple(uid for uid in uids_raw if isinstance(uid, str))
    created = int(entry.get("date") or 0)
    expires_raw = entry.get("expires") or ""
    expires = int(expires_raw) if expires_raw and expires_raw.isdigit() else 0

    primary_serial, is_stub = _token_state(str(entry.get("token_sn") or ""))
    card_serial = primary_serial or str(entry.get("card_sn") or "")
    subkeys = tuple(
        str(fpr).upper() for fpr in entry.get("subkeys", []) if isinstance(fpr, str) and fpr
    )

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
        card_serial=card_serial,
        subkey_fingerprints=subkeys,
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
    # `fpr` records describe whichever key record preceded them, so the parser
    # has to remember whether that was the primary key or one of its subkeys.
    in_subkey = False
    for raw_line in _decode_output(data).splitlines():
        fields = raw_line.split(":")
        if not fields:
            continue
        rec_type = fields[0]
        if rec_type in {"pub", "sec"}:
            in_subkey = False
            current = {
                "type": rec_type,
                "trust": fields[1] if len(fields) > 1 else "",
                "length": fields[2] if len(fields) > 2 else "",
                "algo": fields[3] if len(fields) > 3 else "",
                "date": fields[5] if len(fields) > 5 else "",
                "expires": fields[6] if len(fields) > 6 else "",
                "uids": [],
                "subkeys": [],
                "token_sn": fields[14] if len(fields) > 14 else "",
                "card_sn": _token_state(fields[14] if len(fields) > 14 else "")[0],
            }
            rows.append(current)
        elif rec_type in {"ssb", "sub"} and current is not None:
            in_subkey = True
            # A card-backed key usually keeps its primary offline and only the
            # subkeys on the token, so the token S/N shows up on the `ssb` line.
            # It identifies the device for the whole key, but it says nothing
            # about the primary key's own availability — `token_sn` (the primary
            # record's field 15) stays the authority on that, so a key whose
            # primary is still on disk remains exportable.
            token_sn = fields[14] if len(fields) > 14 else ""
            if not current.get("card_sn"):
                current["card_sn"] = _token_state(token_sn)[0]
        elif rec_type == "fpr" and current is not None and len(fields) > 9:
            if in_subkey:
                # A smartcard reports the fingerprint of the *subkey* in each of
                # its slots, so those have to be recorded to recognise a card's
                # keys in the keyring at all.
                current.setdefault("subkeys", []).append(fields[9])
            else:
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
            if len(record) > 3:
                with contextlib.suppress(ValueError, OSError, OverflowError):
                    signed_at = datetime.fromtimestamp(float(record[3]), tz=UTC)
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


# GnuPG's CARDCTRL status codes (doc/DETAILS) that mean "we cannot talk to a
# card right now": 1 = please insert one, 5 = none available, 6 = no reader.
_CARDCTRL_MISSING = {"1", "5", "6"}

# stderr fragments GnuPG/scdaemon produce for the same situation. Matched
# case-insensitively against the combined status+stderr text.
_CARD_MISSING_MARKERS: tuple[str, ...] = (
    "no such device",
    "card not present",
    "no openpgp card",
    "openpgp card not available",
    "card removed",
    "selecting card failed",
    "no card reader",
    "card error",
)

_CARD_PIN_MARKERS: tuple[str, ...] = (
    "bad pin",
    "wrong pin",
    "invalid pin",
    "pin blocked",
    "card is permanently locked",
    "chv retry counter",
)


def _card_diagnosis(
    records: Iterable[Sequence[str]],
    combined_text: str,
) -> tuple[type[GPGCardError], str] | None:
    """Classify a failed run as a card problem, or return ``None``.

    Card failures are separated from passphrase failures because the remedy is
    different — plug the token in (or stop retrying a blocked PIN) rather than
    retype a passphrase.
    """
    lowered = combined_text.lower()
    if any(marker in lowered for marker in _CARD_PIN_MARKERS):
        return GPGCardPinError, (
            "the smartcard PIN was rejected — check the remaining attempts before retrying"
        )
    for record in records:
        if len(record) > 1 and record[0] == "CARDCTRL" and record[1] in _CARDCTRL_MISSING:
            return GPGCardError, "no smartcard is available — insert your token and try again"
    if any(marker in lowered for marker in _CARD_MISSING_MARKERS):
        return GPGCardError, "no smartcard is available — insert your token and try again"
    return None


def _raise_for_card_failure(
    records: Iterable[Sequence[str]],
    combined_text: str,
    *,
    operation: str,
) -> None:
    """Raise the matching card error when a failed run blames the token."""
    diagnosis = _card_diagnosis(records, combined_text)
    if diagnosis is None:
        return
    error_type, reason = diagnosis
    # GnuPG's own text rides along: the normalised reason cannot tell a missing
    # scdaemon from a switched-off card interface, and those need different fixes.
    raise error_type(f"{operation} failed: {reason}", diagnostics=combined_text)


def _decryption_fingerprint(records: Iterable[Sequence[str]]) -> str | None:
    """Return the secret-key fingerprint GPG used for a successful decrypt."""
    for record in records:
        if len(record) > 1 and record[0] == "DECRYPTION_KEY":
            return record[1]
    return None


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


# Upper bound on buffered status output so a runaway GPG cannot OOM us.
_STATUS_BUF_LIMIT = 1 * 1024 * 1024


def _drain_pipe(fd: int, buffer: bytearray, *, limit: int) -> None:
    """Read ``fd`` into ``buffer`` until EOF (or ``limit``), then close ``fd``.

    Runs on a worker thread draining GPG's dedicated status pipe. Owns ``fd``:
    it is always closed here on exit.
    """
    try:
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                return
            if len(buffer) + len(chunk) > limit:
                return
            buffer.extend(chunk)
    except OSError:
        return
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _write_passphrase_pipe(fd: int, secret: bytearray) -> None:
    """Write ``secret`` + newline to ``fd``, then close ``fd`` and zero ``secret``.

    Runs on a worker thread feeding GPG's ``--passphrase-fd``. Owns ``fd`` (always
    closed here) and wipes the passphrase bytes as soon as they are written so a
    plaintext copy does not linger.
    """
    try:
        _write_all(fd, memoryview(secret))
        _write_all(fd, b"\n")
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)
        if secret:
            zero_mutable_buffer(secret)


def _validated_passphrase_bytes(passphrase: SecureBytes | bytes | None) -> bytearray:
    """Copy the passphrase into a mutable buffer, rejecting framing bytes.

    NUL terminates many C string paths inside pinentry helpers; CR/LF would
    prematurely close the ``--passphrase-fd`` line. The buffer is zeroed before
    raising so no unwiped copy is left behind.
    """
    if passphrase is None:
        return bytearray()
    buf = (
        bytearray(passphrase.view())
        if isinstance(passphrase, SecureBytes)
        else bytearray(passphrase)
    )
    for framing_byte in (0x00, 0x0A, 0x0D):
        if framing_byte in buf:
            zero_mutable_buffer(buf)
            raise GPGValidationError("passphrase must not contain NUL or newline characters")
    return buf


class _GPGPipes:
    """fd lifecycle for the optional status and passphrase pipes of one GPG run.

    Child ends (``pass_read``, ``status_write``) are inherited by the subprocess
    and closed in the parent right after spawn. Parent ends (``pass_write``,
    ``status_read``) are handed off to the writer/drain threads via ``take_*()``,
    which then own and close them. ``close_owned()`` closes whatever was not
    handed off (the error paths) and is safe to call repeatedly.
    """

    def __init__(self, *, status: bool, passphrase: bool) -> None:
        self.pass_read: int | None = None
        self.pass_write: int | None = None
        self.status_read: int | None = None
        self.status_write: int | None = None
        if status:
            self.status_read, self.status_write = os.pipe()
            os.set_inheritable(self.status_write, True)
        if passphrase:
            self.pass_read, self.pass_write = os.pipe()
            os.set_inheritable(self.pass_read, True)

    def child_fds(self) -> tuple[int, ...]:
        return tuple(fd for fd in (self.pass_read, self.status_write) if fd is not None)

    def close_child_ends(self) -> None:
        if self.pass_read is not None:
            os.close(self.pass_read)
            self.pass_read = None
        if self.status_write is not None:
            os.close(self.status_write)
            self.status_write = None

    def take_status_read(self) -> int | None:
        fd = self.status_read
        self.status_read = None
        return fd

    def take_pass_write(self) -> int | None:
        fd = self.pass_write
        self.pass_write = None
        return fd

    def close_owned(self) -> None:
        for fd in (self.pass_read, self.pass_write, self.status_read, self.status_write):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
        self.pass_read = self.pass_write = self.status_read = self.status_write = None


@dataclass(frozen=True)
class CardStatusOutput:
    """What ``gpg --card-status`` said, and what it complained about."""

    colons: str
    diagnostics: str


@dataclass
class PromptRun:
    """Result of an interactive editor run driven by a :class:`PromptScript`."""

    returncode: int
    stdout: bytes
    stderr: bytes
    status: bytes
    # The first prompt the script had no answer for, if any. Its presence means
    # the run was aborted rather than completed.
    unanswered_prompt: str | None = None

    def status_records(self) -> list[list[str]]:
        """The `[GNUPG:]` records GnuPG emitted, split into fields."""
        return _parse_status(self.status)


# GnuPG announces a prompt as `[GNUPG:] GET_LINE <keyword>` (also GET_BOOL for
# yes/no questions and GET_HIDDEN for secrets).
_PROMPT_PREFIXES = ("GET_LINE", "GET_BOOL", "GET_HIDDEN")


def _answer_prompts(
    status_fd: int,
    command_fd: int,
    script: PromptScript,
    transcript: bytearray,
    outcome: dict[str, str],
) -> None:
    """Answer GnuPG's prompts from ``script`` until the status stream ends.

    Runs on a worker thread and owns both fds. A prompt the script cannot answer
    stops the conversation: the command pipe is closed, which makes GnuPG abort
    the operation rather than proceed on a guess. The offending keyword is
    reported through ``outcome`` so the user can be told what was asked.
    """
    buffer = bytearray()
    answering = True
    try:
        while True:
            chunk = os.read(status_fd, 4096)
            if not chunk:
                return
            if len(transcript) + len(chunk) <= _STATUS_BUF_LIMIT:
                transcript.extend(chunk)
            buffer.extend(chunk)
            while b"\n" in buffer:
                line, _, rest = bytes(buffer).partition(b"\n")
                buffer = bytearray(rest)
                if not answering:
                    continue
                keyword = _prompt_keyword(line)
                if keyword is None:
                    continue
                answer = script.take(keyword)
                if answer is None:
                    outcome.setdefault("unanswered", keyword)
                    answering = False
                    with contextlib.suppress(OSError):
                        os.close(command_fd)
                    continue
                try:
                    _write_all(command_fd, answer + b"\n")
                finally:
                    if isinstance(answer, bytes):
                        del answer
    except OSError:
        return
    finally:
        with contextlib.suppress(OSError):
            os.close(status_fd)
        if answering:
            with contextlib.suppress(OSError):
                os.close(command_fd)


def _prompt_keyword(line: bytes) -> str | None:
    """Extract the prompt keyword from one `[GNUPG:]` status line."""
    text = line.decode("utf-8", errors="replace").strip()
    if not text.startswith("[GNUPG:] "):
        return None
    parts = text.removeprefix("[GNUPG:] ").split()
    if len(parts) < 2 or parts[0] not in _PROMPT_PREFIXES:
        return None
    return parts[1]


def _start_status_reader(fd: int | None, buffer: bytearray) -> threading.Thread | None:
    """Start the drain thread for GPG's status pipe; the thread owns ``fd``."""
    if fd is None:
        return None
    thread = threading.Thread(
        target=_drain_pipe,
        args=(fd, buffer),
        kwargs={"limit": _STATUS_BUF_LIMIT},
        daemon=True,
    )
    thread.start()
    return thread


def _start_passphrase_writer(fd: int | None, secret: bytearray) -> threading.Thread | None:
    """Start the writer thread for ``--passphrase-fd``; the thread owns ``fd``."""
    if fd is None:
        return None
    thread = threading.Thread(target=_write_passphrase_pipe, args=(fd, secret), daemon=True)
    thread.start()
    return thread


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
        pass_bytes = _validated_passphrase_bytes(passphrase)
        pipes = _GPGPipes(status=status_fd, passphrase=passphrase is not None)

        cmd = self._base_cmd()
        if pipes.status_write is not None:
            cmd.extend(["--status-fd", str(pipes.status_write)])
        if pipes.pass_read is not None:
            reject_passphrase_in_argv(cmd, pass_bytes)
            cmd.extend(["--passphrase-fd", str(pipes.pass_read)])
        cmd.extend(args)
        reject_passphrase_in_argv(cmd, pass_bytes)

        status_buf = bytearray()
        pass_writer: threading.Thread | None = None
        status_reader: threading.Thread | None = None
        try:
            proc = subprocess.Popen(  # noqa: S603
                cmd,
                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=pipes.child_fds(),
                env=_clean_env(),
                close_fds=True,
            )
            pipes.close_child_ends()
            # take_*() hands fd ownership to each thread, so the finally block
            # does not also try to close those fds. The writer thread zeroes
            # pass_bytes after the write; the finally block re-zeroes as a
            # backstop (idempotent).
            status_reader = _start_status_reader(pipes.take_status_read(), status_buf)
            pass_writer = _start_passphrase_writer(pipes.take_pass_write(), pass_bytes)
            stdout, stderr = self._communicate(proc, input_data)
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
            pipes.close_owned()
            if pass_writer is not None:
                pass_writer.join(timeout=1.0)
            if status_reader is not None and status_reader.is_alive():
                status_reader.join(timeout=1.0)
            if pass_bytes:
                zero_mutable_buffer(pass_bytes)

    def _communicate(
        self,
        proc: subprocess.Popen[bytes],
        input_data: bytes | bytearray | memoryview | None,
    ) -> tuple[bytes, bytes]:
        try:
            return proc.communicate(
                input=cast(bytes | None, input_data),
                timeout=self._config.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            raise GPGProcessError(
                f"GPG operation timed out after {self._config.timeout_seconds}s"
            ) from None

    # ------------------------------------------------------------------ inventory

    def _secret_storage(self) -> dict[str, KeyInfo]:
        """Map every secret-key fingerprint to the parsed secret-listing entry.

        The public listing carries no token information at all, so where a key's
        private half lives (local disk vs. hardware token) can only be learned
        from the secret listing — hence this single cross-reference.
        """
        proc = self._run_gpg(["--with-colons", "--fingerprint", "--list-secret-keys"])
        _require_ok(proc, "failed to list secret keys")
        rows: Iterable[dict[str, Any]] = _parse_colons_keys(proc.stdout)
        infos = (_to_key_info(row) for row in rows if row.get("fingerprint"))
        return {info.fingerprint: info for info in infos}

    def list_keys(self, *, secret: bool = False) -> list[KeyInfo]:
        args = ["--with-colons", "--fingerprint", "--list-secret-keys" if secret else "--list-keys"]
        proc = self._run_gpg(args)
        _require_ok(proc, f"failed to list {'secret ' if secret else ''}keys")
        rows = _parse_colons_keys(proc.stdout)
        # A secret listing implies every row has a private key; for a public
        # listing we cross-reference the secret keys once, carrying over where
        # the private half lives so smartcard-backed keys stay recognisable
        # there too.
        secret_keys: dict[str, KeyInfo] = {} if secret else self._secret_storage()
        infos: list[KeyInfo] = []
        for row in rows:
            info = _to_key_info(row)
            if secret:
                info = info.model_copy(update={"has_private_key": True})
            elif info.fingerprint in secret_keys:
                secret_info = secret_keys[info.fingerprint]
                info = info.model_copy(
                    update={
                        "has_private_key": True,
                        "is_stub": secret_info.is_stub,
                        "card_serial": secret_info.card_serial,
                    }
                )
            infos.append(info)
        return infos

    # ----------------------------------------------------------------- smartcard

    def run_prompt_script(self, args: Sequence[str], script: PromptScript) -> PromptRun:
        """Drive an interactive GnuPG editor (`--card-edit`, `--edit-key`).

        GnuPG announces each prompt on the status pipe and reads the answer from
        a second, app-owned pipe passed as ``--command-fd``; the answers come
        from ``script``, keyed by prompt. Secrets therefore never appear in
        ``argv`` — same guarantee as the passphrase pipe — and a prompt the
        script does not cover aborts the run instead of being guessed at.

        ``--batch`` is deliberately dropped here: GnuPG refuses its editors in
        batch mode. Loopback pinentry is kept, so no external Pinentry is
        spawned; the PIN prompts arrive on the command pipe like every other
        answer.
        """
        self._assert_binary_not_swapped()

        status_read, status_write = os.pipe()
        command_read, command_write = os.pipe()
        os.set_inheritable(status_write, True)
        os.set_inheritable(command_read, True)

        cmd = [
            str(self._config.binary_path),
            "--homedir",
            str(self._config.home_dir),
            "--pinentry-mode",
            "loopback",
            "--status-fd",
            str(status_write),
            "--command-fd",
            str(command_read),
            *args,
        ]

        transcript = bytearray()
        outcome: dict[str, str] = {}
        responder: threading.Thread | None = None
        try:
            proc = subprocess.Popen(  # noqa: S603
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(status_write, command_read),
                env=_clean_env(),
                close_fds=True,
            )
            os.close(status_write)
            os.close(command_read)
            status_write = command_read = -1
            responder = threading.Thread(
                target=_answer_prompts,
                args=(status_read, command_write, script, transcript, outcome),
                daemon=True,
            )
            responder.start()
            status_read = command_write = -1
            stdout, stderr = self._communicate(proc, None)
            responder.join(timeout=2.0)
            return PromptRun(
                returncode=proc.returncode,
                stdout=stdout or b"",
                stderr=stderr or b"",
                status=bytes(transcript),
                unanswered_prompt=outcome.get("unanswered"),
            )
        finally:
            for fd in (status_read, status_write, command_read, command_write):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            if responder is not None and responder.is_alive():
                responder.join(timeout=1.0)

    def card_status(self) -> CardStatusOutput:
        """Return ``gpg --card-status --with-colons`` output plus its diagnostics.

        Running this also makes GnuPG "learn" the inserted card: it creates the
        secret-key stubs in our own homedir for every card key whose public key
        is already in the keyring, which is what makes decrypt/sign work here.

        GnuPG reports "there is no usable card" in two different ways — a
        non-zero exit, or exit 0 with an empty card record and the real reason on
        stderr — so the diagnostics are returned rather than dropped. They are
        what lets the UI say *why* nothing was found instead of only *that*.
        """
        proc = self._run_gpg(["--card-status", "--with-colons"], status_fd=True)
        diagnostics = _decode_output(proc.stderr)
        if proc.returncode != 0:
            combined = _decode_output(proc.status) + "\n" + diagnostics
            _raise_for_card_failure(_parse_status(proc.status), combined, operation="card status")
            raise GPGCardError(
            f"could not read the smartcard: {diagnostics[:200]}", diagnostics=combined
        )
        return CardStatusOutput(colons=_decode_output(proc.stdout), diagnostics=diagnostics)

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
    ) -> tuple[bytes, str | None, SignatureStatus, str | None]:
        """Return plaintext plus signature and decryption-key metadata.

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
            # A smartcard-backed key fails with "no secret key" too when the
            # token is simply unplugged; classify that before the passphrase
            # branch so the user is told to insert it.
            _raise_for_card_failure(
                _parse_status(proc.status), combined, operation="decryption"
            )
            if "bad_passphrase" in combined or "bad passphrase" in combined or "no secret key" in combined:
                raise GPGPassphraseError(f"decryption failed: {detail}")
            raise GPGProcessError(f"decryption failed: {detail}")
        records = _parse_status(proc.status)
        status, signer, _ = _evaluate_signature(records)
        decrypted_with = _decryption_fingerprint(records)
        return bytes(proc.stdout or b""), signer, status, decrypted_with

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
            stderr_text = _decode_output(proc.stderr)
            _raise_for_card_failure(
                _parse_status(proc.status),
                _decode_output(proc.status) + "\n" + stderr_text,
                operation="signing",
            )
            raise GPGProcessError(f"signing failed: {stderr_text[:200]}")
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
        # A non-zero exit that produced no status records means the GPG process
        # itself failed (e.g. OOM kill, missing home dir) rather than a bad sig.
        # Surface that as ERROR so callers don't mistake a process crash for
        # "unsigned data".  Exit 1 is gpg's own "signature bad" code and is
        # covered by the status records already parsed above.
        if status is SignatureStatus.NONE and proc.returncode not in (0, 1):
            return SignatureStatus.ERROR, None, None
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
