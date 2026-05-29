"""Small shared Qt construction helpers used across views.

These were previously copy-pasted into individual views — a monospace-font
probe in four places and a non-editable table cell in four. Centralised here so
the font candidate list and the cell flag are defined exactly once.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QTableWidgetItem

_MONOSPACE_CANDIDATES = ("Cascadia Code", "Fira Code", "Consolas", "Courier New", "Monospace")


def monospace_font(point_size: int = 9) -> QFont:
    """Return a fixed-pitch font, preferring a known-good monospace family."""
    families = QFontDatabase.families()
    for candidate in _MONOSPACE_CANDIDATES:
        if candidate in families:
            font = QFont(candidate)
            font.setPointSize(point_size)
            return font
    font = QFont()
    font.setFixedPitch(True)
    font.setPointSize(point_size)
    return font


def read_only_cell(text: str) -> QTableWidgetItem:
    """A ``QTableWidgetItem`` the user cannot edit in place."""
    item = QTableWidgetItem(text)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item
