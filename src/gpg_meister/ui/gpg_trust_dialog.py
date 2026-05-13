"""Trust-pinning dialog for GPG binaries outside the standard whitelist (planv2.md §9.2).

Shown when:
- A user-configured GPG path is not in the platform whitelist and has no pinned hash yet.
- A previously pinned binary's hash no longer matches (binary was updated or replaced).

The user must explicitly accept before the binary is executed. Acceptance persists the
SHA-256 in config so subsequent launches re-verify without prompting (unless it changes).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QClipboard, QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)


def _fmt_sha256(sha256: str) -> str:
    """Split SHA-256 into 8-char groups for readability."""
    return " ".join(sha256[i : i + 8] for i in range(0, len(sha256), 8))


class GpgTrustDialog(QDialog):
    """Ask the user to explicitly accept an out-of-whitelist or changed GPG binary."""

    def __init__(
        self,
        path: Path,
        new_sha: str,
        *,
        mismatch: bool = False,
        old_sha: str | None = None,
        parent: object = None,
    ) -> None:
        super().__init__(parent)  # type: ignore[call-arg]
        self._path = path
        self._new_sha = new_sha
        self._mismatch = mismatch
        self._old_sha = old_sha
        self.setWindowTitle("GPG Binary — Trust Confirmation Required")
        self.setMinimumWidth(580)
        self.setModal(True)
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Warning banner
        banner = QFrame()
        banner.setFrameShape(QFrame.Shape.StyledPanel)
        banner_color = "#7a1f1f" if self._mismatch else "#7a4f1f"
        banner.setStyleSheet(f"background-color: {banner_color}; border-radius: 4px; padding: 8px;")
        banner_layout = QVBoxLayout(banner)
        banner_layout.setContentsMargins(10, 8, 10, 8)

        if self._mismatch:
            headline = QLabel("⚠  GPG Binary Has Changed")
            body_text = (
                "The GPG binary you previously approved has a different SHA-256 fingerprint "
                "than the one on disk. This can happen after a package update, but it could "
                "also indicate that the binary was replaced by a third party.\n\n"
                "Verify the new fingerprint independently before accepting."
            )
        else:
            headline = QLabel("⚠  GPG Binary Outside Standard Whitelist")
            body_text = (
                "The configured GPG binary is not in the standard installation paths "
                "for your platform. GPG Meister will not execute it without your explicit "
                "approval.\n\n"
                "Verify that this is a genuine GnuPG binary before accepting."
            )

        headline.setStyleSheet("color: #ffffff; font-weight: bold; font-size: 13px;")
        banner_layout.addWidget(headline)
        layout.addWidget(banner)

        explanation = QLabel(body_text)
        explanation.setWordWrap(True)
        explanation.setStyleSheet("color: #dddddd;")
        layout.addWidget(explanation)

        # Path
        layout.addWidget(QLabel("<b>Binary path:</b>"))
        path_label = QLabel(str(self._path))
        path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        path_label.setStyleSheet("font-family: monospace; background: #1a1a1a; padding: 4px; border-radius: 3px;")
        path_label.setWordWrap(True)
        layout.addWidget(path_label)

        # SHA-256
        if self._mismatch and self._old_sha:
            layout.addWidget(QLabel("<b>Previously trusted SHA-256:</b>"))
            old_box = self._sha_widget(self._old_sha, copyable=False)
            old_box.setStyleSheet("font-family: monospace; background: #1a1a1a; color: #ff8888; padding: 4px; border-radius: 3px;")
            layout.addWidget(old_box)
            layout.addWidget(QLabel("<b>New SHA-256 on disk:</b>"))
        else:
            layout.addWidget(QLabel("<b>SHA-256 fingerprint:</b>"))

        sha_row = QHBoxLayout()
        sha_display = QTextEdit()
        sha_display.setReadOnly(True)
        sha_display.setPlainText(_fmt_sha256(self._new_sha))
        sha_display.setFixedHeight(52)
        sha_display.setStyleSheet(
            "font-family: monospace; background: #1a1a1a; color: #88ff88; padding: 4px; border-radius: 3px;"
        )
        sha_row.addWidget(sha_display, stretch=1)

        copy_btn = QPushButton("Copy")
        copy_btn.setFixedWidth(60)
        copy_btn.clicked.connect(self._copy_sha)
        sha_row.addWidget(copy_btn)
        layout.addLayout(sha_row)

        # Buttons
        buttons = QDialogButtonBox()
        accept_btn = buttons.addButton("Accept and pin", QDialogButtonBox.ButtonRole.AcceptRole)
        accept_btn.setStyleSheet("background-color: #5a1f1f; font-weight: bold;")
        buttons.addButton("Cancel — exit", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _sha_widget(self, sha256: str, *, copyable: bool) -> QLabel:
        label = QLabel(_fmt_sha256(sha256))
        label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse if copyable
            else Qt.TextInteractionFlag.NoTextInteraction
        )
        label.setWordWrap(True)
        return label

    def _copy_sha(self) -> None:
        cb: QClipboard = QGuiApplication.clipboard()
        cb.setText(self._new_sha)
