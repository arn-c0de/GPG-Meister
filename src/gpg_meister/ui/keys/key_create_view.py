"""Key creation dialog (planv2.md §14, Ed25519 default per §13.2)."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo
from gpg_meister.services.key_service import KeyService
from gpg_meister.ui.keys.key_create_viewmodel import KeyCreateViewModel
from gpg_meister.ui.widgets.passphrase_field import PassphraseField

_ALGO_CHOICES: list[tuple[str, KeyAlgorithm, int]] = [
    ("Ed25519 + Curve25519 (recommended)", KeyAlgorithm.EDDSA, 255),
    ("RSA 4096", KeyAlgorithm.RSA, 4096),
    ("RSA 3072", KeyAlgorithm.RSA, 3072),
]

_EXPIRY_CHOICES = [
    ("1 year", "1y"),
    ("2 years", "2y"),
    ("3 years", "3y"),
    ("5 years", "5y"),
    ("Never", "0"),
]


class KeyCreateDialog(QDialog):
    """Modal dialog for creating a new GPG key pair.

    Signals
    -------
    key_created: emitted with the new KeyInfo after successful creation.
    """

    key_created: Signal = Signal(object)

    def __init__(self, key_service: KeyService, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("New Key Pair")
        self.setMinimumWidth(440)
        self._vm = KeyCreateViewModel(key_service, parent=self)
        self._build_ui()
        self._connect_signals()
        self._vm._emit_validity()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addLayout(self._build_identity_form())
        self._add_token_fields(layout)
        self._add_passphrase_fields(layout)
        self._add_status_widgets(layout)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Create Key")
        self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        self._buttons.accepted.connect(self._on_submit)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

    def _build_identity_form(self) -> QFormLayout:
        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)

        self._name_field = _line_edit("Name", "Your Name")
        form.addRow("Name:", self._name_field)
        self._email_field = _line_edit("Email", "you@example.com")
        form.addRow("Email:", self._email_field)
        self._label_field = _line_edit("Label", "Optional internal label")
        form.addRow("Label:", self._label_field)
        self._platform_field = _line_edit("Platform", "GitHub, Laptop, Server, ...")
        form.addRow("Platform:", self._platform_field)
        self._purpose_field = _line_edit("Purpose", "Code signing, email, backup, ...")
        form.addRow("Purpose:", self._purpose_field)

        self._notes_field = QTextEdit()
        self._notes_field.setPlaceholderText("Optional notes")
        self._notes_field.setAccessibleName("Notes")
        self._notes_field.setMaximumHeight(90)
        form.addRow("Notes:", self._notes_field)

        self._algo_combo = QComboBox()
        for label, _algo, _length in _ALGO_CHOICES:
            self._algo_combo.addItem(label)
        self._algo_combo.setCurrentIndex(0)
        form.addRow("Algorithm:", self._algo_combo)

        self._expiry_combo = QComboBox()
        for label, _val in _EXPIRY_CHOICES:
            self._expiry_combo.addItem(label)
        self._expiry_combo.setCurrentIndex(1)
        form.addRow("Expires:", self._expiry_combo)
        return form

    def _add_token_fields(self, layout: QVBoxLayout) -> None:
        """The security-key option, and the two follow-up choices it unlocks."""
        self._use_token = QCheckBox("Unlock this key with a security key instead of typing a passphrase")
        self._use_token.setVisible(self._vm.supports_token)
        layout.addWidget(self._use_token)

        self._token_hint = QLabel(
            "The key's passphrase is generated and never shown. Your security key "
            "reproduces it on demand — you enter its PIN and touch it. Enrolling "
            "asks for two touches."
        )
        self._token_hint.setWordWrap(True)
        self._token_hint.setVisible(False)
        layout.addWidget(self._token_hint)

        # "FIDO2" is spelled out because a YubiKey 5 carries two unrelated PINs,
        # and the OpenPGP one — the PIN most users have already set — is not the
        # one asked for here.
        self._pin_label = QLabel("Security key FIDO2 PIN:")
        self._pin_label.setVisible(False)
        layout.addWidget(self._pin_label)
        self._pin_field = PassphraseField(show_strength=False)
        self._pin_field.setPlaceholderText("FIDO2 PIN of your security key…")
        self._pin_field.setVisible(False)
        layout.addWidget(self._pin_field)

        self._token_only = QCheckBox("No emergency passphrase — only this security key can open it")
        self._token_only.setVisible(False)
        layout.addWidget(self._token_only)

        self._token_only_warning = QLabel(
            "If this security key is lost or breaks, the key is gone for good. "
            "Nothing in this application, and no backup of this computer, can "
            "bring it back."
        )
        self._token_only_warning.setStyleSheet("color: #cc0000;")
        self._token_only_warning.setWordWrap(True)
        self._token_only_warning.setVisible(False)
        layout.addWidget(self._token_only_warning)

    def _add_passphrase_fields(self, layout: QVBoxLayout) -> None:
        self._passphrase_label = QLabel("Passphrase:")
        layout.addWidget(self._passphrase_label)
        self._passphrase_field = PassphraseField(show_strength=True)
        self._passphrase_field.setPlaceholderText("New key passphrase…")
        layout.addWidget(self._passphrase_field)

        self._confirm_label = QLabel("Confirm passphrase:")
        layout.addWidget(self._confirm_label)
        self._confirm_field = PassphraseField(show_strength=False)
        self._confirm_field.setPlaceholderText("Repeat passphrase…")
        layout.addWidget(self._confirm_field)

        self._mismatch_label = QLabel("")
        self._mismatch_label.setStyleSheet("color: #cc0000;")
        layout.addWidget(self._mismatch_label)

    def _add_status_widgets(self, layout: QVBoxLayout) -> None:
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedHeight(6)
        self._progress.hide()
        layout.addWidget(self._progress)

        self._error_label = QLabel("")
        self._error_label.setStyleSheet("color: #cc0000;")
        self._error_label.setWordWrap(True)
        self._error_label.hide()
        layout.addWidget(self._error_label)

    def _connect_signals(self) -> None:
        self._name_field.textChanged.connect(self._vm.set_name)
        self._email_field.textChanged.connect(self._vm.set_email)
        self._label_field.textChanged.connect(self._vm.set_label)
        self._platform_field.textChanged.connect(self._vm.set_platform)
        self._purpose_field.textChanged.connect(self._vm.set_purpose)
        self._notes_field.textChanged.connect(
            lambda: self._vm.set_notes(self._notes_field.toPlainText())
        )
        self._algo_combo.currentIndexChanged.connect(self._on_algo_changed)
        self._expiry_combo.currentIndexChanged.connect(self._on_expiry_changed)
        self._passphrase_field.passphrase_changed.connect(
            lambda: self._vm.set_passphrase(self._passphrase_field.text())
        )
        self._passphrase_field.passphrase_changed.connect(self._check_mismatch)
        self._confirm_field.passphrase_changed.connect(
            lambda: self._vm.set_confirm(self._confirm_field.text())
        )
        self._confirm_field.passphrase_changed.connect(self._check_mismatch)

        self._use_token.toggled.connect(self._on_use_token_toggled)
        self._token_only.toggled.connect(self._on_token_only_toggled)
        self._pin_field.passphrase_changed.connect(
            lambda: self._vm.set_pin(self._pin_field.text())
        )
        self._vm.touch_requested.connect(self._on_touch_requested)

        self._vm.form_valid_changed.connect(
            lambda ok: self._buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(ok)
        )
        self._vm.loading_changed.connect(self._on_loading)
        self._vm.operation_succeeded.connect(self._on_success)
        self._vm.operation_failed.connect(self._on_error)

    def _on_algo_changed(self, index: int) -> None:
        _, algo, length = _ALGO_CHOICES[index]
        self._vm.set_algorithm(algo, length)

    def _on_expiry_changed(self, index: int) -> None:
        _, value = _EXPIRY_CHOICES[index]
        self._vm.set_expiry(value)

    def _on_use_token_toggled(self, checked: bool) -> None:
        self._vm.set_use_token(checked)
        self._token_hint.setVisible(checked)
        self._pin_label.setVisible(checked)
        self._pin_field.setVisible(checked)
        self._token_only.setVisible(checked)
        if not checked:
            # Un-ticking must not leave a token-only form behind, or the next
            # submit would create a key with no unlock method at all.
            self._token_only.setChecked(False)
            self._pin_field.clear()
        self._update_passphrase_visibility()

    def _on_token_only_toggled(self, checked: bool) -> None:
        self._vm.set_token_only(checked)
        self._token_only_warning.setVisible(checked)
        self._update_passphrase_visibility()

    def _update_passphrase_visibility(self) -> None:
        """Hide the passphrase fields only when nothing will be done with them."""
        wanted = not (self._use_token.isChecked() and self._token_only.isChecked())
        for widget in (
            self._passphrase_label,
            self._passphrase_field,
            self._confirm_label,
            self._confirm_field,
        ):
            widget.setVisible(wanted)
        self._passphrase_label.setText(
            "Emergency passphrase:" if self._use_token.isChecked() else "Passphrase:"
        )
        if not wanted:
            self._passphrase_field.clear()
            self._confirm_field.clear()

    def _on_touch_requested(self) -> None:
        self._token_hint.setText("Touch your security key now — it is waiting.")

    def _check_mismatch(self) -> None:
        pp = self._passphrase_field.text()
        confirm = self._confirm_field.text()
        if confirm and pp != confirm:
            self._mismatch_label.setText("Passphrases do not match.")
        else:
            self._mismatch_label.setText("")

    def _on_loading(self, loading: bool) -> None:
        if loading:
            self._progress.show()
        else:
            self._progress.hide()
        self._buttons.setEnabled(not loading)
        self._name_field.setEnabled(not loading)
        self._email_field.setEnabled(not loading)
        self._label_field.setEnabled(not loading)
        self._platform_field.setEnabled(not loading)
        self._purpose_field.setEnabled(not loading)
        self._notes_field.setEnabled(not loading)

    def _on_submit(self) -> None:
        self._error_label.hide()
        self._vm.submit()
        self._passphrase_field.clear()
        self._confirm_field.clear()

    def _on_success(self, key: KeyInfo) -> None:
        self.key_created.emit(key)
        self.accept()

    def _on_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.show()


def _line_edit(accessible_name: str, placeholder: str) -> QLineEdit:
    field = QLineEdit()
    field.setPlaceholderText(placeholder)
    field.setAccessibleName(accessible_name)
    return field
