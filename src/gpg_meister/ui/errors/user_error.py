"""UserError dataclass for surfacing errors to the UI (planv2.md §14.1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ErrorSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class UserError:
    """A typed, translatable error intended for display in the UI.

    code:    Unique identifier used to look up the catalog entry.
    args:    Named substitution values for the message template.
    severity: Visual prominence of the error in the UI.
    """

    code: str
    args: dict[str, str] = field(default_factory=dict)
    severity: ErrorSeverity = ErrorSeverity.ERROR
