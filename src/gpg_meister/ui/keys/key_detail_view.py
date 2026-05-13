"""Read-only key detail dialog (planv2.md §4.8)."""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo, TrustLevel
from gpg_meister.services.key_service import KeyService
from gpg_meister.ui.widgets.clipboard_button import ClipboardButton
from gpg_meister.ui.widgets.fingerprint_label import FingerprintLabel

_TRUST_LABELS: dict[TrustLevel, tuple[str, str]] = {
    TrustLevel.ULTIMATE: ("Ultimate (owned by you)", "color: #004400"),
    TrustLevel.FULL: ("Full — verified", "color: #006600"),
    TrustLevel.MARGINAL: ("Marginal", "color: #887700"),
    TrustLevel.NEVER: ("Never trusted", "color: #cc0000"),
    TrustLevel.UNKNOWN: ("Unknown — not verified", "color: #666666"),
}


class KeyDetailView(QDialog):
    """Non-modal details dialog for a single key."""

    def __init__(
        self, key: KeyInfo, key_service: KeyService, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Key Details")
        self.setMinimumWidth(520)
        self._key = key
        self._svc = key_service
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        uid_text = "\n".join(self._key.user_ids) or "—"
        uid_label = QLabel(uid_text)
        uid_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        form.addRow("User IDs:", uid_label)

        fp_widget = FingerprintLabel(self._key.fingerprint)
        form.addRow("Fingerprint:", fp_widget)

        form.addRow("Algorithm:", QLabel(self._key.algorithm.value))
        form.addRow("Key length:", QLabel(str(self._key.length)))
        form.addRow("Created:", QLabel(self._key.created_at.strftime("%Y-%m-%d")))

        if self._key.expires_at:
            exp_str = self._key.expires_at.strftime("%Y-%m-%d")
            expired = datetime.now(tz=UTC) >= self._key.expires_at
            exp_label = QLabel(exp_str + (" (expired)" if expired else ""))
            if expired:
                exp_label.setStyleSheet("color: #cc0000;")
        else:
            exp_label = QLabel("Does not expire")
        form.addRow("Expires:", exp_label)

        has_priv_label = QLabel("Yes — private key available" if self._key.has_private_key else "No")
        form.addRow("Private key:", has_priv_label)

        trust_text, trust_style = _TRUST_LABELS.get(
            self._key.trust, ("Unknown", "color: #666666")
        )
        trust_label = QLabel(trust_text)
        trust_label.setStyleSheet(trust_style)
        form.addRow("Trust:", trust_label)

        if self._key.is_revoked:
            revoked_label = QLabel("This key has been revoked.")
            revoked_label.setStyleSheet("color: #cc0000; font-weight: bold;")
            form.addRow("", revoked_label)

        layout.addLayout(form)

        export_btn = ClipboardButton("Copy Public Key")
        export_btn.sensitive_copy.connect(lambda: None)
        export_btn.clicked.connect(self._copy_public_key)
        layout.addWidget(export_btn)

        self._armor_view = QTextEdit()
        self._armor_view.setReadOnly(True)
        self._armor_view.setFont(_monospace_font())
        self._armor_view.setMaximumHeight(120)
        self._armor_view.setPlaceholderText("Public key will appear here after clicking Copy Public Key")
        layout.addWidget(self._armor_view)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _copy_public_key(self) -> None:
        try:
            armored = self._svc.export_public(self._key.fingerprint)
            self._armor_view.setPlainText(armored)
            from PySide6.QtWidgets import QApplication
            cb = QApplication.clipboard()
            if cb:
                cb.setText(armored)
        except Exception as exc:
            self._armor_view.setPlainText(f"Error: {exc}")


def _monospace_font() -> QFont:
    from PySide6.QtGui import QFont, QFontDatabase
    families = QFontDatabase.families()
    for candidate in ("Cascadia Code", "Fira Code", "Consolas", "Courier New", "Monospace"):
        if candidate in families:
            f = QFont(candidate)
            f.setPointSize(9)
            return f
    f = QFont()
    f.setFixedPitch(True)
    f.setPointSize(9)
    return f
