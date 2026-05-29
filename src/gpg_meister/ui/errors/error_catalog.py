"""Maps internal error codes to user-facing message templates (planv2.md §14.1).

Every ViewModelError is translated through this catalog before reaching the View.
Templates use named placeholders so translators can reorder tokens.

Actions offered are symbolic strings; the View maps them to buttons.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass

from gpg_meister.ui.errors.user_error import ErrorSeverity

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CatalogEntry:
    code: str
    title: str
    message: str
    actions: tuple[str, ...]
    severity: ErrorSeverity = ErrorSeverity.ERROR
    help_section: str = ""


# Each entry's code is written once as the first positional argument; the lookup
# dict below is keyed by it, so the code is never repeated as a dict key too.
_ENTRIES: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        "vault_decryption_failed",
        title="Vault could not be opened",
        message=(
            "The vault could not be opened. The passphrase may be wrong, "
            "or the file may be damaged or tampered with."
        ),
        actions=("retry", "cancel"),
        help_section="troubleshooting",
    ),
    CatalogEntry(
        "gpg_binary_not_found",
        title="GnuPG not found",
        message=(
            "GPG Meister needs GnuPG installed on this computer, but none was found. "
            "GnuPG is the underlying program that performs the cryptography."
        ),
        actions=("open_install_guide", "choose_path"),
        help_section="troubleshooting",
    ),
    CatalogEntry(
        "gpg_version_too_old",
        title="GnuPG version too old",
        message=(
            "Your installed GnuPG (version {version}) is too old. "
            "GPG Meister requires version 2.2.0 or newer."
        ),
        actions=("open_upgrade_guide",),
        help_section="troubleshooting",
    ),
    CatalogEntry(
        "key_expired",
        title="Key expired",
        message=(
            "The key for {uid} expired on {date}. "
            "Encrypted messages may not be decryptable by the recipient."
        ),
        actions=("continue_anyway", "cancel"),
        severity=ErrorSeverity.WARNING,
    ),
    CatalogEntry(
        "key_revoked",
        title="Key revoked",
        message=(
            "The key for {uid} was revoked by its owner. "
            "Do not use this key — the owner has marked it as compromised or replaced."
        ),
        actions=("cancel",),
    ),
    CatalogEntry(
        "key_not_trusted",
        title="Key not verified",
        message=(
            "You have not marked {fingerprint} as trusted. "
            "Verify it through a separate channel (e.g., phone call) "
            "before sending sensitive data."
        ),
        actions=("verify_and_trust", "continue_once", "cancel"),
        severity=ErrorSeverity.WARNING,
    ),
    CatalogEntry(
        "signature_invalid",
        title="Invalid signature",
        message=(
            "The signature on this message is invalid. "
            "The message may have been altered after signing, "
            "or the signer's key was not the one expected."
        ),
        actions=("show_details",),
    ),
    CatalogEntry(
        "signer_unknown",
        title="Unknown signer",
        message=(
            "This message was signed by an unknown key ({fingerprint}). "
            "Import the signer's public key to verify the signature."
        ),
        actions=("import_key",),
        severity=ErrorSeverity.WARNING,
    ),
    CatalogEntry(
        "vault_format_error",
        title="Not a valid vault",
        message=(
            "This file does not look like a GPG Meister vault. "
            "It may be corrupted or of a different format."
        ),
        actions=("choose_another_file",),
    ),
    CatalogEntry(
        "vault_checksum_mismatch",
        title="Vault checksum mismatch",
        message=(
            "The vault's checksum does not match. "
            "The file may have been damaged during transfer."
        ),
        actions=("open_anyway", "cancel"),
        severity=ErrorSeverity.WARNING,
    ),
    CatalogEntry(
        "low_entropy_passphrase",
        title="Passphrase too weak",
        message=(
            "This passphrase is too easy to guess. "
            "Use at least 4 unrelated words or 12 mixed characters."
        ),
        actions=(),
        severity=ErrorSeverity.WARNING,
    ),
    CatalogEntry(
        "key_not_found",
        title="Key not found",
        message="The requested key could not be found in your keyring.",
        actions=("cancel",),
    ),
    CatalogEntry(
        "config_error",
        title="Configuration problem",
        message=(
            "Your configuration could not be loaded or saved. "
            "Check that the config file is intact and has safe permissions."
        ),
        actions=("cancel",),
    ),
    CatalogEntry(
        "gpg_operation_failed",
        title="GnuPG operation failed",
        message=(
            "The GnuPG operation could not be completed. "
            "The passphrase may be wrong, or the key may be missing or unusable."
        ),
        actions=("retry", "cancel"),
        help_section="troubleshooting",
    ),
    CatalogEntry(
        "unexpected_error",
        title="Something went wrong",
        message=(
            "The operation failed unexpectedly. The technical details were written "
            "to the diagnostic log under reference {ref}."
        ),
        actions=("cancel",),
    ),
)

_CATALOG: dict[str, CatalogEntry] = {entry.code: entry for entry in _ENTRIES}


def lookup(code: str) -> CatalogEntry | None:
    """Return the catalog entry for a given error code, or None."""
    return _CATALOG.get(code)


def format_message(code: str, **kwargs: str) -> str:
    """Return the formatted user-facing message for a code, substituting kwargs."""
    entry = _CATALOG.get(code)
    if entry is None:
        return f"An unexpected error occurred (code: {code})."
    try:
        return entry.message.format(**kwargs)
    except KeyError:
        return entry.message


def message_for_exception(exc: BaseException) -> str:
    """Map internal exceptions to a user-facing message.

    Known exception types map to curated catalog entries. ``ValueError`` carries
    intentional, user-facing validation text (raised throughout the services
    layer) and is shown as-is. Every other exception is treated as unexpected:
    rather than echo ``str(exc)`` — which can leak file paths, key ids or raw
    gpg stderr into the UI — we show a generic message with a short correlation
    reference and write the real detail to the (scrubbed) diagnostic log.
    """
    name = type(exc).__name__
    code = {
        "DecryptionError": "vault_decryption_failed",
        "VaultFormatError": "vault_format_error",
        "VaultChecksumMismatchError": "vault_checksum_mismatch",
        "GPGKeyNotFoundError": "key_not_found",
        "ConfigServiceError": "config_error",
        "GPGProcessError": "gpg_operation_failed",
        "GPGPassphraseError": "gpg_operation_failed",
        "GPGValidationError": "gpg_operation_failed",
    }.get(name)
    if code is not None:
        return format_message(code)
    if isinstance(exc, ValueError):
        return str(exc)

    # Unknown/unexpected exception: do not surface raw exception text in the UI.
    ref = secrets.token_hex(3)
    _log.error("unexpected error [ref=%s]: %s", ref, type(exc).__name__, exc_info=exc)
    return format_message("unexpected_error", ref=ref)
