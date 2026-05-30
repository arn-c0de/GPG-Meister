"""Encrypt-tab view (planv2.md §4.8, §14.2 recipient confirmation panel)."""

from __future__ import annotations

from datetime import UTC, datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo, TrustLevel
from gpg_meister.models.message import EncryptResult
from gpg_meister.ui.clipboard import copy_text
from gpg_meister.ui.messages.encrypt_viewmodel import EncryptViewModel
from gpg_meister.ui.qt_helpers import monospace_font
from gpg_meister.ui.widgets.passphrase_field import PassphraseField

_TRUST_LABELS: dict[TrustLevel, tuple[str, str]] = {
    TrustLevel.ULTIMATE: ("Verified (owned by you)", "#004400"),
    TrustLevel.FULL: ("Verified", "#006600"),
    TrustLevel.MARGINAL: ("Partially trusted", "#887700"),
    TrustLevel.NEVER: ("Not trusted", "#cc0000"),
    TrustLevel.UNKNOWN: ("Unknown trust", "#666666"),
}


def _fmt_date(dt: datetime | None) -> str:
    if dt is None:
        return "no expiry"
    return dt.strftime("%Y-%m-%d")


def _is_expired(key: KeyInfo) -> bool:
    if key.expires_at is None:
        return False
    return datetime.now(tz=UTC) >= key.expires_at


class _RecipientCard(QFrame):
    """Displays trust details for a single recipient key (§14.2)."""

    def __init__(self, key: KeyInfo, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(2)

        uid_label = QLabel(key.primary_user_id)
        uid_label.setTextFormat(Qt.TextFormat.PlainText)
        uid_label.setStyleSheet("font-weight: bold;")
        uid_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        layout.addWidget(uid_label)

        fp_groups = " ".join(
            key.fingerprint[i : i + 4] for i in range(0, len(key.fingerprint), 4)
        )
        fp_label = QLabel(fp_groups)
        fp_label.setFont(monospace_font())
        fp_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(fp_label)

        meta = f"Created {_fmt_date(key.created_at)}  |  Expires: {_fmt_date(key.expires_at)}"
        layout.addWidget(QLabel(meta))

        trust_text, trust_color = _TRUST_LABELS.get(key.trust, ("Unknown", "#666666"))
        trust_label = QLabel(trust_text)
        trust_label.setStyleSheet(f"color: {trust_color}; font-weight: bold;")
        layout.addWidget(trust_label)

        if key.is_revoked:
            rev_label = QLabel("REVOKED")
            rev_label.setStyleSheet("color: #cc0000; font-weight: bold;")
            layout.addWidget(rev_label)
        elif _is_expired(key):
            exp_label = QLabel("EXPIRED")
            exp_label.setStyleSheet("color: #cc0000; font-weight: bold;")
            layout.addWidget(exp_label)


class EncryptView(QWidget):
    """Encrypt tab: compose message, select recipients, confirm, encrypt."""

    def __init__(
        self,
        viewmodel: EncryptViewModel,
        *,
        clipboard_clear_seconds: int = 60,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._vm = viewmodel
        self._clipboard_clear_seconds = clipboard_clear_seconds
        self._available_keys: list[KeyInfo] = []
        self._recipient_keys: list[KeyInfo] = []
        self._build_ui()
        self._connect_signals()
        self._vm.load_keys()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        splitter = QSplitter(Qt.Orientation.Vertical)
        root.addWidget(splitter, stretch=1)

        # --- Top: plaintext input + recipient controls ---
        top_widget = QWidget()
        top_layout = QVBoxLayout(top_widget)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(4)

        top_layout.addWidget(QLabel("Message to encrypt:"))
        self._plaintext = QTextEdit()
        self._plaintext.setPlaceholderText("Paste or type the plaintext message here…")
        self._plaintext.setAcceptRichText(False)
        top_layout.addWidget(self._plaintext, stretch=1)

        # Recipient row
        recip_box = QGroupBox("Recipients")
        recip_layout = QVBoxLayout(recip_box)

        recip_add_row = QHBoxLayout()
        self._recip_combo = QComboBox()
        self._recip_combo.setPlaceholderText("Select a key to add…")
        self._recip_combo.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self._btn_add_recip = QPushButton("Add")
        self._btn_remove_recip = QPushButton("Remove")
        self._btn_remove_recip.setEnabled(False)
        recip_add_row.addWidget(self._recip_combo, stretch=1)
        recip_add_row.addWidget(self._btn_add_recip)
        recip_add_row.addWidget(self._btn_remove_recip)
        recip_layout.addLayout(recip_add_row)

        self._recip_list = QListWidget()
        self._recip_list.setMaximumHeight(80)
        recip_layout.addWidget(self._recip_list)
        top_layout.addWidget(recip_box)

        # Optional sign-with
        sign_box = QGroupBox("Sign (optional)")
        sign_box.setCheckable(True)
        sign_box.setChecked(False)
        sign_layout = QHBoxLayout(sign_box)
        self._sign_combo = QComboBox()
        self._sign_combo.setPlaceholderText("Select signing key…")
        self._sign_combo.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self._sign_passphrase = PassphraseField(show_strength=False)
        self._sign_passphrase.setPlaceholderText("Signing key passphrase…")
        sign_layout.addWidget(self._sign_combo, stretch=1)
        sign_layout.addWidget(self._sign_passphrase, stretch=1)
        self._sign_box = sign_box
        top_layout.addWidget(sign_box)

        splitter.addWidget(top_widget)

        # --- Bottom: confirmation panel + output ---
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        bottom_layout.setSpacing(4)

        bottom_layout.addWidget(QLabel("Recipient confirmation (§14.2):"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setMaximumHeight(180)
        self._confirm_container = QWidget()
        self._confirm_inner = QVBoxLayout(self._confirm_container)
        self._confirm_inner.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._confirm_inner.setSpacing(4)
        scroll.setWidget(self._confirm_container)
        bottom_layout.addWidget(scroll)

        self._verify_check = QCheckBox("I have verified the recipients listed above")
        self._verify_check.setEnabled(False)
        bottom_layout.addWidget(self._verify_check)

        btn_row = QHBoxLayout()
        self._btn_encrypt = QPushButton("Encrypt")
        self._btn_encrypt.setEnabled(False)
        self._btn_clear = QPushButton("Clear")
        btn_row.addWidget(self._btn_encrypt)
        btn_row.addWidget(self._btn_clear)
        btn_row.addStretch()
        bottom_layout.addLayout(btn_row)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedHeight(4)
        self._progress.hide()
        bottom_layout.addWidget(self._progress)

        self._error_label = QLabel()
        self._error_label.setStyleSheet("color: #cc0000;")
        self._error_label.setWordWrap(True)
        self._error_label.hide()
        bottom_layout.addWidget(self._error_label)

        output_box = QGroupBox("Encrypted output")
        output_layout = QVBoxLayout(output_box)
        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setMaximumHeight(120)
        self._output.setPlaceholderText("Encrypted message will appear here…")
        self._btn_copy_output = QPushButton("Copy to Clipboard")
        self._btn_copy_output.setEnabled(False)
        output_layout.addWidget(self._output)
        output_layout.addWidget(self._btn_copy_output)
        bottom_layout.addWidget(output_box)

        splitter.addWidget(bottom_widget)

    def _connect_signals(self) -> None:
        self._vm.keys_loaded.connect(self._on_keys_loaded)
        self._vm.loading_changed.connect(self._on_loading)
        self._vm.operation_succeeded.connect(self._on_success)
        self._vm.operation_failed.connect(self._on_error)

        self._plaintext.textChanged.connect(
            self._on_plaintext_changed
        )
        self._btn_add_recip.clicked.connect(self._add_recipient)
        self._btn_remove_recip.clicked.connect(self._remove_recipient)
        self._recip_list.itemSelectionChanged.connect(self._on_recip_selection)
        self._sign_box.toggled.connect(self._on_sign_toggled)
        self._sign_combo.currentIndexChanged.connect(self._on_sign_key_changed)
        self._verify_check.toggled.connect(self._on_verify_toggled)
        self._btn_encrypt.clicked.connect(self._submit)
        self._btn_clear.clicked.connect(self._clear)
        self._btn_copy_output.clicked.connect(self._copy_output)

    def _on_keys_loaded(self, keys: list[KeyInfo]) -> None:
        self._available_keys = keys
        self._recip_combo.clear()
        self._sign_combo.clear()
        self._sign_combo.addItem("(none)", None)
        for key in keys:
            label = key.display_label
            self._recip_combo.addItem(label, key)
            if key.has_private_key:
                self._sign_combo.addItem(label, key)

    def _add_recipient(self) -> None:
        idx = self._recip_combo.currentIndex()
        if idx < 0:
            return
        key = self._recip_combo.itemData(idx)
        if not isinstance(key, KeyInfo):
            return
        if any(k.fingerprint == key.fingerprint for k in self._recipient_keys):
            return
        self._recipient_keys.append(key)
        item = QListWidgetItem(key.display_label)
        item.setData(Qt.ItemDataRole.UserRole, key)
        self._recip_list.addItem(item)
        self._vm.set_recipients([k.fingerprint for k in self._recipient_keys])
        self._rebuild_confirm_panel()
        self._update_encrypt_button()

    def _remove_recipient(self) -> None:
        row = self._recip_list.currentRow()
        if row < 0 or row >= len(self._recipient_keys):
            return
        self._recipient_keys.pop(row)
        self._recip_list.takeItem(row)
        self._vm.set_recipients([k.fingerprint for k in self._recipient_keys])
        self._rebuild_confirm_panel()
        self._verify_check.setChecked(False)
        self._update_encrypt_button()

    def _on_recip_selection(self) -> None:
        self._btn_remove_recip.setEnabled(self._recip_list.currentRow() >= 0)

    def _on_sign_toggled(self, checked: bool) -> None:
        if not checked:
            self._vm.set_sign_with(None)
            self._sign_passphrase.clear()

    def _on_sign_key_changed(self, idx: int) -> None:
        if not self._sign_box.isChecked():
            return
        key = self._sign_combo.itemData(idx)
        if isinstance(key, KeyInfo):
            self._vm.set_sign_with(key.fingerprint)
        else:
            self._vm.set_sign_with(None)

    def _rebuild_confirm_panel(self) -> None:
        while self._confirm_inner.count():
            item = self._confirm_inner.takeAt(0)
            if item is not None:
                w = item.widget()
                if w is not None:
                    w.deleteLater()

        if self._recipient_keys:
            for key in self._recipient_keys:
                card = _RecipientCard(key)
                self._confirm_inner.addWidget(card)
            self._verify_check.setEnabled(not self._has_blocked_recipient())
        else:
            placeholder = QLabel("No recipients added yet.")
            placeholder.setStyleSheet("color: #888888;")
            self._confirm_inner.addWidget(placeholder)
            self._verify_check.setEnabled(False)
            self._verify_check.setChecked(False)

    def _on_verify_toggled(self, checked: bool) -> None:
        self._vm.set_trust_confirmed(checked)
        self._update_encrypt_button()

    def _update_encrypt_button(self) -> None:
        can = self._vm.can_submit() and not self._has_blocked_recipient()
        self._btn_encrypt.setEnabled(can)

    def _on_loading(self, loading: bool) -> None:
        if loading:
            self._progress.show()
        else:
            self._progress.hide()
        self._btn_encrypt.setEnabled(not loading and self._vm.can_submit())

    def _on_success(self, result: object) -> None:
        if not isinstance(result, EncryptResult):
            return
        self._error_label.hide()
        self._output.setPlainText(result.armored_ciphertext)
        self._btn_copy_output.setEnabled(True)

    def _on_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.show()

    def _clear(self) -> None:
        self._plaintext.clear()
        self._recipient_keys.clear()
        self._recip_list.clear()
        self._vm.set_recipients([])
        self._rebuild_confirm_panel()
        self._verify_check.setChecked(False)
        self._output.clear()
        self._btn_copy_output.setEnabled(False)
        self._error_label.hide()

    def _on_plaintext_changed(self) -> None:
        self._vm.set_plaintext(self._plaintext.toPlainText())
        self._update_encrypt_button()

    def _has_blocked_recipient(self) -> bool:
        return any(key.is_revoked or key.is_expired for key in self._recipient_keys)

    def _copy_output(self) -> None:
        text = self._output.toPlainText()
        copy_text(text, clear_after_seconds=self._clipboard_clear_seconds)

    def _submit(self) -> None:
        # Pass the field's text accessor so the ViewModel reads the passphrase
        # once at submit and never stores it (L7).
        self._vm.submit(self._sign_passphrase.text)
        self._sign_passphrase.clear()
