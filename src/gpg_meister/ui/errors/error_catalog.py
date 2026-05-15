"""Maps internal error codes to user-facing message templates (planv2.md §14.1).

Every ViewModelError is translated through this catalog before reaching the View.
Templates use named placeholders so translators can reorder tokens.

Actions offered are symbolic strings; the View maps them to buttons.
"""

from __future__ import annotations

from dataclasses import dataclass

from gpg_meister.ui.errors.user_error import ErrorSeverity


@dataclass(frozen=True)
class CatalogEntry:
    code: str
    title: str
    message: str
    actions: tuple[str, ...]
    severity: ErrorSeverity = ErrorSeverity.ERROR
    help_section: str = ""


_CATALOG: dict[str, CatalogEntry] = {
    "vault_decryption_failed": CatalogEntry(
        code="vault_decryption_failed",
        title="Vault could not be opened",
        message=(
            "The vault could not be opened. The passphrase may be wrong, "
            "or the file may be damaged or tampered with."
        ),
        actions=("retry", "cancel"),
        help_section="troubleshooting",
    ),
    "gpg_binary_not_found": CatalogEntry(
        code="gpg_binary_not_found",
        title="GnuPG not found",
        message=(
            "GPG Meister needs GnuPG installed on this computer, but none was found. "
            "GnuPG is the underlying program that performs the cryptography."
        ),
        actions=("open_install_guide", "choose_path"),
        help_section="troubleshooting",
    ),
    "gpg_version_too_old": CatalogEntry(
        code="gpg_version_too_old",
        title="GnuPG version too old",
        message=(
            "Your installed GnuPG (version {version}) is too old. "
            "GPG Meister requires version 2.2.0 or newer."
        ),
        actions=("open_upgrade_guide",),
        help_section="troubleshooting",
    ),
    "key_expired": CatalogEntry(
        code="key_expired",
        title="Key expired",
        message=(
            "The key for {uid} expired on {date}. "
            "Encrypted messages may not be decryptable by the recipient."
        ),
        actions=("continue_anyway", "cancel"),
        severity=ErrorSeverity.WARNING,
    ),
    "key_revoked": CatalogEntry(
        code="key_revoked",
        title="Key revoked",
        message=(
            "The key for {uid} was revoked by its owner. "
            "Do not use this key — the owner has marked it as compromised or replaced."
        ),
        actions=("cancel",),
    ),
    "key_not_trusted": CatalogEntry(
        code="key_not_trusted",
        title="Key not verified",
        message=(
            "You have not marked {fingerprint} as trusted. "
            "Verify it through a separate channel (e.g., phone call) "
            "before sending sensitive data."
        ),
        actions=("verify_and_trust", "continue_once", "cancel"),
        severity=ErrorSeverity.WARNING,
    ),
    "signature_invalid": CatalogEntry(
        code="signature_invalid",
        title="Invalid signature",
        message=(
            "The signature on this message is invalid. "
            "The message may have been altered after signing, "
            "or the signer's key was not the one expected."
        ),
        actions=("show_details",),
    ),
    "signer_unknown": CatalogEntry(
        code="signer_unknown",
        title="Unknown signer",
        message=(
            "This message was signed by an unknown key ({fingerprint}). "
            "Import the signer's public key to verify the signature."
        ),
        actions=("import_key",),
        severity=ErrorSeverity.WARNING,
    ),
    "vault_format_error": CatalogEntry(
        code="vault_format_error",
        title="Not a valid vault",
        message=(
            "This file does not look like a GPG Meister vault. "
            "It may be corrupted or of a different format."
        ),
        actions=("choose_another_file",),
    ),
    "vault_checksum_mismatch": CatalogEntry(
        code="vault_checksum_mismatch",
        title="Vault checksum mismatch",
        message=(
            "The vault's checksum does not match. "
            "The file may have been damaged during transfer."
        ),
        actions=("open_anyway", "cancel"),
        severity=ErrorSeverity.WARNING,
    ),
    "low_entropy_passphrase": CatalogEntry(
        code="low_entropy_passphrase",
        title="Passphrase too weak",
        message=(
            "This passphrase is too easy to guess. "
            "Use at least 4 unrelated words or 12 mixed characters."
        ),
        actions=(),
        severity=ErrorSeverity.WARNING,
    ),
}


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
    """Map internal exceptions to a generic user-facing message."""
    name = type(exc).__name__
    code = {
        "DecryptionError": "vault_decryption_failed",
        "VaultFormatError": "vault_format_error",
        "GPGKeyNotFoundError": "key_not_found",
        "ConfigServiceError": "config_error",
    }.get(name)
    if code is not None:
        return format_message(code)
    if isinstance(exc, ValueError):
        return str(exc)
    
    # Fallback: include the actual error message so users can debug without logs.
    msg = str(exc).strip()
    if msg:
        return f"The operation failed: {msg}"
    return "The operation failed. Check the diagnostic log for details."
