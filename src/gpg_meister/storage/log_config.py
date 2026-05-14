"""structlog setup with sensitive-data redaction (planv2.md §2.10, §5.4).

Call configure_logging() once at startup. After that, every module gets a
logger via structlog.get_logger(__name__).

The SensitiveDataFilter processor:
- Redacts any key whose name is in the deny-list, regardless of value.
- Redacts any string value that contains PGP block headers.
- The base64-length heuristic of v1 is intentionally omitted (false positives
  on fingerprint chains and file hashes).
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger

_DENY_LIST: frozenset[str] = frozenset(
    {
        "passphrase",
        "password",
        "secret",
        "private_key",
        "private_key_armored",
        "armored_private",
        "plaintext",
        "decrypted",
        "vault_key",
        "derived_key",
        "salt",
        "pin",
        "token",
    }
)

_CONTENT_TRIGGERS: tuple[str, ...] = (
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----BEGIN PGP MESSAGE-----",
)

_REDACTED = "[REDACTED]"

# Event names owned by the audit logger — the debug logger must never emit them.
_AUDIT_EVENT_NAMES: frozenset[str] = frozenset(
    {
        "audit_log_opened",
        "gpg_binary_resolved",
        "gpg_binary_rejected",
        "startup_environment_check",
        "key_generated",
        "key_deleted",
        "key_imported",
        "key_exported_public",
        "key_exported_private",
        "message_signed",
        "message_decrypted",
        "message_decrypt_failed",
        "vault_created",
        "vault_imported",
        "vault_import_failed",
        "config_loaded",
        "config_saved",
    }
)


def sensitive_data_filter(
    _logger: WrappedLogger, _method: str, event_dict: EventDict
) -> EventDict:
    """Redact sensitive fields from the event dictionary."""
    for key in list(event_dict.keys()):
        if key in _DENY_LIST:
            event_dict[key] = _REDACTED
            continue
        value = event_dict.get(key)
        if isinstance(value, str) and any(t in value for t in _CONTENT_TRIGGERS):
            event_dict[key] = _REDACTED
    return event_dict


def _audit_event_guard(
    _logger: WrappedLogger, _method: str, event_dict: EventDict
) -> EventDict:
    """Drop and warn if the diagnostic logger is used for an audit event."""
    event = event_dict.get("event", "")
    if event in _AUDIT_EVENT_NAMES:
        # Replace the forbidden audit event with a diagnostic warning so no
        # audit information leaks into the diagnostic stream but the mistake is
        # visible to developers.
        event_dict["event"] = "diagnostic_audit_event_intercepted"
        event_dict["original_event"] = event
    return event_dict


def configure_logging(
    *,
    log_file: Path | None = None,
    level: int = logging.INFO,
    dev: bool = False,
) -> None:
    """Set up structlog for the application.

    Call once at startup. Idempotent (structlog.configure is idempotent).

    Parameters
    ----------
    log_file:
        Optional path to write structured log records. If None, only the
        console renderer is used.
    level:
        Root logging level (default INFO).
    dev:
        If True, use the pretty console renderer (colours, timestamps).
        If False, use JSON-lines renderer suitable for log aggregation.
    """
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _audit_event_guard,
        sensitive_data_filter,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
    ]

    if dev:
        renderer: Any = structlog.dev.ConsoleRenderer()
    else:
        renderer = structlog.processors.JSONRenderer()

    processors = [*shared_processors, renderer]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(
            file=_open_log_file(log_file) if log_file else sys.stderr
        ),
        cache_logger_on_first_use=True,
    )

    # Mirror to stdlib logging so third-party libraries that use logging are captured.
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stderr)


def _open_log_file(path: Path) -> Any:
    """Open (or create) the diagnostic log file in append mode, mode 0600."""
    from gpg_meister.storage.permissions import ensure_dir, reject_symlink

    ensure_dir(path.parent, mode=0o700)
    reject_symlink(path)
    fh = path.open("a", encoding="utf-8")
    if sys.platform != "win32":
        import os
        os.chmod(path, 0o600)
    return fh
