"""Key detail dialog with optional context editing."""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import Qt, QThreadPool, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo, KeyStorage, TrustLevel
from gpg_meister.services.key_service import KeyService
from gpg_meister.ui.qt_helpers import monospace_font
from gpg_meister.ui.widgets.clipboard_button import ClipboardButton
from gpg_meister.ui.widgets.fingerprint_label import FingerprintLabel
from gpg_meister.ui.worker import Worker

_TRUST_LABELS: dict[TrustLevel, tuple[str, str]] = {
    TrustLevel.ULTIMATE: ("Ultimate (owned by you)", "color: #004400"),
    TrustLevel.FULL: ("Full — verified", "color: #006600"),
    TrustLevel.MARGINAL: ("Marginal", "color: #887700"),
    TrustLevel.NEVER: ("Never trusted", "color: #cc0000"),
    TrustLevel.UNKNOWN: ("Unknown — not verified", "color: #666666"),
}


def _private_key_text(key: KeyInfo) -> str:
    if key.storage is KeyStorage.SMARTCARD:
        return f"Yes — uses {key.storage_label}, unlocked with the card PIN"
    if key.storage is KeyStorage.OFFLINE:
        return "Known, but the secret key is not stored on this computer"
    return "Yes — private key available" if key.has_private_key else "No"


class KeyDetailView(QDialog):
    """Details dialog for a single key."""

    key_updated: Signal = Signal(object)

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
        self._add_key_facts(form)
        self._add_context_fields(form)
        layout.addLayout(form)

        self._add_public_key_section(layout)
        self._add_buttons(layout)
        self._set_edit_mode(False)

    def _add_key_facts(self, form: QFormLayout) -> None:
        """Read-only properties of the key: identity, dates, trust, status."""
        uid_label = QLabel("\n".join(self._key.user_ids) or "—")
        uid_label.setTextFormat(Qt.TextFormat.PlainText)
        uid_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        form.addRow("User IDs:", uid_label)

        form.addRow("Fingerprint:", FingerprintLabel(self._key.fingerprint))
        form.addRow("Algorithm:", QLabel(self._key.algorithm.value))
        form.addRow("Key length:", QLabel(str(self._key.length)))
        form.addRow("Created:", QLabel(self._key.created_at.strftime("%Y-%m-%d")))
        form.addRow("Expires:", self._expiry_label())

        form.addRow("Private key:", QLabel(_private_key_text(self._key)))

        storage_label = QLabel(self._key.storage_label)
        storage_label.setTextFormat(Qt.TextFormat.PlainText)
        if self._key.is_on_smartcard:
            storage_label.setStyleSheet("color: #006666; font-weight: bold;")
            storage_label.setToolTip(
                "Decrypting or signing with this key needs the token plugged in "
                "and its PIN — what the device holds cannot leave it."
            )
        form.addRow("Stored on:", storage_label)

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

    def _expiry_label(self) -> QLabel:
        if not self._key.expires_at:
            return QLabel("Does not expire")
        exp_str = self._key.expires_at.strftime("%Y-%m-%d")
        expired = datetime.now(tz=UTC) >= self._key.expires_at
        label = QLabel(exp_str + (" (expired)" if expired else ""))
        if expired:
            label.setStyleSheet("color: #cc0000;")
        return label

    def _add_context_fields(self, form: QFormLayout) -> None:
        """User-editable context metadata (label, platform, purpose, notes)."""
        self._label_input = QLineEdit(self._key.label)
        self._platform_input = QLineEdit(self._key.platform)
        self._purpose_input = QLineEdit(self._key.purpose)
        self._notes_input = QTextEdit()
        self._notes_input.setPlainText(self._key.notes)
        self._notes_input.setMaximumHeight(120)

        form.addRow("Label:", self._label_input)
        form.addRow("Platform:", self._platform_input)
        form.addRow("Purpose:", self._purpose_input)
        form.addRow("Notes:", self._notes_input)

    def _add_public_key_section(self, layout: QVBoxLayout) -> None:
        export_btn = ClipboardButton("Copy Public Key")
        export_btn.sensitive_copy.connect(lambda: None)
        export_btn.clicked.connect(self._copy_public_key)
        layout.addWidget(export_btn)

        self._armor_view = QTextEdit()
        self._armor_view.setReadOnly(True)
        self._armor_view.setFont(monospace_font())
        self._armor_view.setMaximumHeight(120)
        self._armor_view.setPlaceholderText(
            "Public key will appear here after clicking Copy Public Key"
        )
        layout.addWidget(self._armor_view)

    def _add_buttons(self, layout: QVBoxLayout) -> None:
        self._btn_edit = QPushButton("Edit")
        self._btn_edit.clicked.connect(self._toggle_edit_mode)

        self._btn_save = QPushButton("Save")
        self._btn_save.clicked.connect(self._save_context)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.addButton(self._btn_edit, QDialogButtonBox.ButtonRole.ActionRole)
        buttons.addButton(self._btn_save, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _copy_public_key(self) -> None:
        fp = self._key.fingerprint

        def _do() -> str:
            return self._svc.export_public(fp)

        def _on_result(armored: object) -> None:
            if not isinstance(armored, str):
                return
            self._armor_view.setPlainText(armored)
            from gpg_meister.ui.clipboard import copy_text
            copy_text(armored)

        def _on_error(msg: str) -> None:
            self._armor_view.setPlainText(f"Error: {msg}")

        w = Worker(_do)
        w.signals.result.connect(_on_result)
        w.signals.error.connect(_on_error)
        QThreadPool.globalInstance().start(w)

    def _toggle_edit_mode(self) -> None:
        self._set_edit_mode(not self._label_input.isEnabled())

    def _set_edit_mode(self, enabled: bool) -> None:
        self._label_input.setEnabled(enabled)
        self._platform_input.setEnabled(enabled)
        self._purpose_input.setEnabled(enabled)
        self._notes_input.setEnabled(enabled)
        self._btn_save.setEnabled(enabled)
        self._btn_edit.setText("Cancel" if enabled else "Edit")
        if not enabled:
            self._restore_context_fields()

    def _restore_context_fields(self) -> None:
        self._label_input.setText(self._key.label)
        self._platform_input.setText(self._key.platform)
        self._purpose_input.setText(self._key.purpose)
        self._notes_input.setPlainText(self._key.notes)

    def _save_context(self) -> None:
        try:
            updated = self._svc.update_context(
                self._key.fingerprint,
                label=self._label_input.text(),
                platform=self._platform_input.text(),
                purpose=self._purpose_input.text(),
                notes=self._notes_input.toPlainText(),
            )
        except Exception as exc:
            QMessageBox.critical(self, "Save failed", str(exc))
            return

        self._key = updated
        self.key_updated.emit(updated)
        self._set_edit_mode(False)
        QMessageBox.information(self, "Key details saved", "Key usage context was updated.")
