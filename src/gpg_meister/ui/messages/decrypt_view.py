"""Decrypt-tab view (planv2.md §4.8)."""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtGui import QHideEvent
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.message import DecryptResult
from gpg_meister.ui.clipboard import copy_text
from gpg_meister.ui.messages.decrypt_viewmodel import DecryptViewModel
from gpg_meister.ui.qt_helpers import busy_bar, error_label
from gpg_meister.ui.widgets.passphrase_field import PassphraseField


class DecryptView(QWidget):
    """Decrypt tab: paste ciphertext, enter passphrase, reveal plaintext."""

    def __init__(
        self,
        viewmodel: DecryptViewModel,
        *,
        clipboard_clear_seconds: int = 60,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._vm = viewmodel
        self._clipboard_clear_seconds = clipboard_clear_seconds
        self._build_ui()
        self._connect_signals()
        # Auto-clear the revealed plaintext after the same delay used for the
        # clipboard, so decrypted text does not linger on screen / in the widget
        # buffer for the whole session (L8). 0 disables, matching clipboard UX.
        self._output_clear_timer = QTimer(self)
        self._output_clear_timer.setSingleShot(True)
        self._output_clear_timer.timeout.connect(self._clear_output)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        layout.addWidget(QLabel("Encrypted message (PGP armored):"))
        self._ciphertext = QTextEdit()
        self._ciphertext.setPlaceholderText("Paste the -----BEGIN PGP MESSAGE----- block here…")
        self._ciphertext.setAcceptRichText(False)
        layout.addWidget(self._ciphertext, stretch=1)

        hint = QLabel(
            "No manual key selection is needed. GPG reads the recipient from the message "
            "and uses the matching private key from your local keyring. Enter a passphrase "
            "only if that private key is protected."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #666666;")
        layout.addWidget(hint)

        layout.addWidget(QLabel("Passphrase:"))
        self._passphrase = PassphraseField(show_strength=False)
        self._passphrase.setPlaceholderText("Optional: passphrase for the private key…")
        layout.addWidget(self._passphrase)

        btn_row = QHBoxLayout()
        self._btn_decrypt = QPushButton("Decrypt")
        self._btn_decrypt.setEnabled(False)
        self._btn_clear = QPushButton("Clear")
        btn_row.addWidget(self._btn_decrypt)
        btn_row.addWidget(self._btn_clear)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._progress = busy_bar()
        layout.addWidget(self._progress)

        self._error_label = error_label()
        layout.addWidget(self._error_label)

        output_box = QGroupBox("Decrypted plaintext")
        output_layout = QVBoxLayout(output_box)
        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setPlaceholderText("Decrypted text will appear here…")
        self._metadata_label = QLabel()
        self._metadata_label.setWordWrap(True)
        self._metadata_label.hide()
        self._btn_copy_output = QPushButton("Copy to Clipboard")
        self._btn_copy_output.setEnabled(False)
        output_layout.addWidget(self._output, stretch=1)
        output_layout.addWidget(self._metadata_label)
        output_layout.addWidget(self._btn_copy_output)
        layout.addWidget(output_box, stretch=1)

    def _connect_signals(self) -> None:
        self._vm.loading_changed.connect(self._on_loading)
        self._vm.operation_succeeded.connect(self._on_success)
        self._vm.operation_failed.connect(self._on_error)

        self._ciphertext.textChanged.connect(self._on_input_changed)
        self._passphrase.passphrase_changed.connect(self._on_passphrase_changed)
        self._btn_decrypt.clicked.connect(self._submit)
        self._btn_clear.clicked.connect(self._clear)
        self._btn_copy_output.clicked.connect(self._copy_output)

    def _on_input_changed(self) -> None:
        text = self._ciphertext.toPlainText()
        self._vm.set_ciphertext(text)
        self._update_button()

    def _on_passphrase_changed(self) -> None:
        self._update_button()

    def _update_button(self) -> None:
        self._btn_decrypt.setEnabled(self._vm.can_submit())

    def _on_loading(self, loading: bool) -> None:
        if loading:
            self._progress.show()
        else:
            self._progress.hide()
        self._btn_decrypt.setEnabled(not loading and self._vm.can_submit())

    def _on_success(self, result: object) -> None:
        if not isinstance(result, DecryptResult):
            return
        self._error_label.hide()
        try:
            text = result.plaintext.decode("utf-8")
        except UnicodeDecodeError:
            text = repr(result.plaintext)
        self._output.setPlainText(text)
        self._btn_copy_output.setEnabled(True)
        if self._clipboard_clear_seconds > 0:
            self._output_clear_timer.start(self._clipboard_clear_seconds * 1000)

        metadata_lines = []
        if result.decrypted_with_fingerprint:
            metadata_lines.append(f"Decrypted with: {result.decrypted_with_fingerprint}")
        if result.signer_fingerprint:
            from gpg_meister.models.key_info import TrustLevel
            status_label = result.signature_status.summary
            trust = result.signer_trust
            trust_str = f"  trust: {trust.value}"
            untrusted = trust in (TrustLevel.UNKNOWN, TrustLevel.NEVER)
            if result.signature_valid and untrusted:
                status_label = "valid (signer UNTRUSTED)"
            signer = result.signer_fingerprint or "unknown key"
            metadata_lines.append(
                f"Signed by: {signer}  (signature {status_label}{trust_str})"
            )
            if not result.signature_valid:
                color = "#cc0000"
            elif untrusted:
                color = "#cc6600"
            else:
                color = "#006600"
            self._metadata_label.setStyleSheet(f"color: {color};")
        else:
            self._metadata_label.setStyleSheet("color: #444444;")

        if metadata_lines:
            self._metadata_label.setText("\n".join(metadata_lines))
            self._metadata_label.show()
        else:
            self._metadata_label.hide()

    def _on_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.show()

    def _clear(self) -> None:
        self._ciphertext.clear()
        self._passphrase.clear()
        self._clear_output()
        self._error_label.hide()

    def _clear_output(self) -> None:
        """Wipe the revealed plaintext (auto-clear timer, hide, or Clear button)."""
        self._output_clear_timer.stop()
        self._output.clear()
        self._metadata_label.hide()
        self._btn_copy_output.setEnabled(False)

    def hideEvent(self, event: QHideEvent) -> None:
        # Scrub the decrypted plaintext when the tab/window is hidden or closed.
        self._clear_output()
        super().hideEvent(event)

    def _copy_output(self) -> None:
        text = self._output.toPlainText()
        copy_text(text, clear_after_seconds=self._clipboard_clear_seconds)

    def _submit(self) -> None:
        passphrase = self._passphrase.text()
        self._passphrase.clear()
        self._vm.submit(lambda: passphrase)
