"""Binary vault frame: pack/unpack with canonical-JSON header.

Layout (planv2.md §6.1):

    [4 bytes]  Magic: b"GPGV"
    [1 byte ]  Major version: 0x02 (passphrase-derived key) or 0x03 (key slots)
    [4 bytes]  Header JSON length, big-endian uint32
    [N bytes]  Header JSON, UTF-8  (passed verbatim as AAD by vault_service)
    [4 bytes]  Ciphertext length, big-endian uint32
    [M bytes]  Ciphertext (AEAD ciphertext + 16-byte tag)
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass

from pydantic import ValidationError

from gpg_meister.models.vault import (
    SUPPORTED_VAULT_VERSIONS,
    VaultHeader,
)
from gpg_meister.models.vault import (
    VAULT_FORMAT_VERSION as _MODEL_VAULT_FORMAT_VERSION,
)
from gpg_meister.security.errors import VaultFormatError

VAULT_FORMAT_VERSION = _MODEL_VAULT_FORMAT_VERSION
MAGIC = b"GPGV"
MAGIC_LEN = 4
VERSION_LEN = 1
LENGTH_FIELD = 4
HEADER_OFFSET = MAGIC_LEN + VERSION_LEN + LENGTH_FIELD  # 9
# Hard upper bound on header size to prevent integer-overflow / DoS on read.
MAX_HEADER_SIZE = 64 * 1024  # 64 KiB
# Hard upper bound on ciphertext size. 256 MiB is far above the largest realistic
# vault (a few thousand keys ≈ a few MB).
MAX_CIPHERTEXT_SIZE = 256 * 1024 * 1024


@dataclass(frozen=True)
class UnpackedFrame:
    header: VaultHeader
    header_bytes: bytes  # exact bytes of the header window, for use as AAD
    ciphertext: bytes


def header_to_canonical_json(header: VaultHeader) -> bytes:
    """Serialise the header with canonical JSON (sorted keys, no whitespace).

    The byte form is stable across platforms and python versions, which is essential
    because these bytes are fed verbatim into the AEAD as associated data.

    Unset optional fields are omitted rather than written as ``null``, so a
    passphrase-only (v2) header serialises to exactly the bytes it did before
    key slots were introduced.
    """
    obj = header.model_dump(mode="json", exclude_none=True)
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def pack(header: VaultHeader, ciphertext: bytes) -> tuple[bytes, bytes]:
    """Serialise the binary frame.

    Returns `(frame_bytes, header_bytes)` so the caller can reuse the exact header
    bytes as AAD when encrypting (the caller usually generates the ciphertext
    *after* settling on the header bytes).
    """
    header_bytes = header_to_canonical_json(header)
    if len(header_bytes) > MAX_HEADER_SIZE:
        raise VaultFormatError(f"header exceeds {MAX_HEADER_SIZE} bytes")
    if len(ciphertext) > MAX_CIPHERTEXT_SIZE:
        raise VaultFormatError(f"ciphertext exceeds {MAX_CIPHERTEXT_SIZE} bytes")

    frame = (
        MAGIC
        + bytes([header.version])
        + struct.pack(">I", len(header_bytes))
        + header_bytes
        + struct.pack(">I", len(ciphertext))
        + ciphertext
    )
    return frame, header_bytes


def unpack(data: bytes) -> UnpackedFrame:
    """Parse and validate the binary frame.

    All structural problems raise `VaultFormatError`. The header is parsed via the
    `VaultHeader` Pydantic model, so semantic problems (unknown algorithm, wrong
    nonce length) are also caught here.
    """
    if len(data) < HEADER_OFFSET + LENGTH_FIELD:
        raise VaultFormatError("file truncated: not enough bytes for frame header")

    if data[:MAGIC_LEN] != MAGIC:
        raise VaultFormatError("magic bytes do not match — not a GPG Meister vault")

    version = data[MAGIC_LEN]
    if version not in SUPPORTED_VAULT_VERSIONS:
        raise VaultFormatError(
            f"unsupported vault version: {version} "
            f"(expected one of {', '.join(str(v) for v in SUPPORTED_VAULT_VERSIONS)})"
        )

    (header_len,) = struct.unpack(">I", data[MAGIC_LEN + VERSION_LEN : HEADER_OFFSET])
    if header_len == 0 or header_len > MAX_HEADER_SIZE:
        raise VaultFormatError(f"invalid header length: {header_len}")

    header_end = HEADER_OFFSET + header_len
    if len(data) < header_end + LENGTH_FIELD:
        raise VaultFormatError("file truncated: header extends past file end")

    header_bytes = data[HEADER_OFFSET:header_end]

    try:
        header_obj = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultFormatError(f"header is not valid UTF-8 JSON: {exc}") from exc

    try:
        header = VaultHeader.model_validate(header_obj)
    except ValidationError as exc:
        raise VaultFormatError(f"header fields are invalid: {exc}") from exc

    if header.version != version:
        raise VaultFormatError(
            f"frame version {version} does not match header version {header.version}"
        )

    (ct_len,) = struct.unpack(">I", data[header_end : header_end + LENGTH_FIELD])
    if ct_len == 0 or ct_len > MAX_CIPHERTEXT_SIZE:
        raise VaultFormatError(f"invalid ciphertext length: {ct_len}")

    ct_start = header_end + LENGTH_FIELD
    ct_end = ct_start + ct_len
    if len(data) < ct_end:
        raise VaultFormatError("file truncated: ciphertext extends past file end")
    if len(data) > ct_end:
        raise VaultFormatError(
            f"file has {len(data) - ct_end} trailing bytes after ciphertext"
        )

    return UnpackedFrame(
        header=header,
        header_bytes=header_bytes,
        ciphertext=data[ct_start:ct_end],
    )
