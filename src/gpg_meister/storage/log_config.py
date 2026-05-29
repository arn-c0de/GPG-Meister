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
import os
import sys
from pathlib import Path
from typing import Any

import structlog
from structlog.types import EventDict, WrappedLogger

from gpg_meister.storage.secret_keys import contains_secret_marker, is_forbidden_key

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


def _redact(value: Any) -> Any:
    """Recursively redact deny-listed keys and secret-looking string values."""
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, val in value.items():
            if (isinstance(key, str) and is_forbidden_key(key)) or contains_secret_marker(val):
                out[key] = _REDACTED
            else:
                out[key] = _redact(val)
        return out
    if isinstance(value, (list, tuple)):
        redacted = [_REDACTED if contains_secret_marker(item) else _redact(item) for item in value]
        return type(value)(redacted) if isinstance(value, tuple) else redacted
    return value


def sensitive_data_filter(
    _logger: WrappedLogger, _method: str, event_dict: EventDict
) -> EventDict:
    """Redact sensitive fields from the event dictionary, at every nesting depth.

    A deny-listed key (matched case-insensitively by exact name) is redacted
    regardless of value, and any string value carrying a PGP armor header is
    redacted regardless of its key — recursively through nested dicts and lists
    so a secret one level deep cannot slip through (L9).
    """
    redacted = _redact(dict(event_dict))
    event_dict.clear()
    event_dict.update(redacted)
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
    open_flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), open_flags, 0o600)
    fh = os.fdopen(fd, "a", encoding="utf-8", closefd=True)
    if sys.platform != "win32":
        os.fchmod(fh.fileno(), 0o600)
    return fh
