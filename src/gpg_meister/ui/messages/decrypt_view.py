"""Decrypt-tab view (planv2.md §4.8)."""

from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtGui import QHideEvent, QShowEvent
from PySide6.QtWidgets import (
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.models.message import DecryptResult
from gpg_meister.services.key_service import KeyService
from gpg_meister.services.key_unlock_service import KeyUnlockService
from gpg_meister.services.smartcard_service import CardSyncResult
from gpg_meister.ui.clipboard import copy_text
from gpg_meister.ui.messages.decrypt_viewmodel import DecryptViewModel
from gpg_meister.ui.qt_helpers import busy_bar, error_label
from gpg_meister.ui.widgets.passphrase_field import PassphraseField
from gpg_meister.ui.widgets.token_unlock_dialog import TokenUnlockDialog, token_backed_keys


class DecryptView(QWidget):
    """Decrypt tab: paste ciphertext, enter passphrase, reveal plaintext."""

    def __init__(
        self,
        viewmodel: DecryptViewModel,
        *,
        clipboard_clear_seconds: int = 60,
        unlock: KeyUnlockService | None = None,
        key_service: KeyService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._vm = viewmodel
        self._clipboard_clear_seconds = clipboard_clear_seconds
        # Both are needed to offer the security-key route: one to know which
        # keys are enrolled, the other to list them. Without either, the button
        # simply never appears.
        self._unlock = unlock
        self._key_service = key_service
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

        # Shown only once a smartcard-backed key is in play, so the passphrase
        # field stops looking like the wrong place to type a PIN.
        self._card_hint = QLabel()
        self._card_hint.setWordWrap(True)
        self._card_hint.hide()
        layout.addWidget(self._card_hint)

        self._passphrase_label = QLabel("Passphrase:")
        layout.addWidget(self._passphrase_label)
        self._passphrase = PassphraseField(show_strength=False)
        self._passphrase.setPlaceholderText("Optional: passphrase for the private key…")
        layout.addWidget(self._passphrase)

        btn_row = QHBoxLayout()
        self._btn_decrypt = QPushButton("Decrypt")
        self._btn_decrypt.setEnabled(False)
        self._btn_token = QPushButton("Decrypt with security key…")
        self._btn_token.setEnabled(False)
        self._btn_token.setVisible(False)
        self._btn_clear = QPushButton("Clear")
        btn_row.addWidget(self._btn_decrypt)
        btn_row.addWidget(self._btn_token)
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
        self._vm.card_changed.connect(self._on_card_changed)

        self._ciphertext.textChanged.connect(self._on_input_changed)
        self._passphrase.passphrase_changed.connect(self._on_passphrase_changed)
        self._btn_decrypt.clicked.connect(self._submit)
        self._btn_token.clicked.connect(self._submit_with_token)
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
        self._btn_token.setEnabled(self._vm.can_submit())

    def _on_loading(self, loading: bool) -> None:
        self._progress.setVisible(loading)
        self._btn_decrypt.setEnabled(not loading and self._vm.can_submit())
        self._btn_token.setEnabled(not loading and self._vm.can_submit())

    def _token_backed_keys(self) -> list[KeyInfo]:
        if self._unlock is None or self._key_service is None:
            return []
        return token_backed_keys(self._unlock, self._key_service.list_keys())

    def _refresh_token_button(self) -> None:
        """Offer the security-key route only when a key is actually enrolled."""
        self._btn_token.setVisible(bool(self._token_backed_keys()))

    def _submit_with_token(self) -> None:
        if self._unlock is None:
            return
        keys = self._token_backed_keys()
        if not keys:
            self._refresh_token_button()
            return
        dialog = TokenUnlockDialog(self._unlock, keys, parent=self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        secret = dialog.take_secret()
        if secret is None:  # pragma: no cover - accepted implies a secret
            return
        self._error_label.hide()
        # Ownership moves to the viewmodel, which closes it once the attempt
        # is over — successful or not.
        self._vm.submit_with_secret(secret)

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
            metadata_lines.append(f"Signed by: {signer}  (signature {status_label}{trust_str})")
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
        # A failure is the moment a pulled-out token matters most; re-probe so
        # the hint reflects reality before the user retries.
        self._vm.refresh_card()

    def _on_card_changed(self, result: object) -> None:
        """Relabel the credential field when a token key can decrypt this message."""
        if not isinstance(result, CardSyncResult) or not result.keys:
            self._card_hint.hide()
            self._passphrase_label.setText("Passphrase:")
            self._passphrase.setPlaceholderText("Optional: passphrase for the private key…")
            return

        names = ", ".join(sorted({key.storage_label for key in result.keys}))
        if result.card is None:
            self._card_hint.setText(
                f"A key in your keyring lives on {names}. Plug the token in before "
                "decrypting a message addressed to it."
            )
            self._card_hint.setStyleSheet("color: #cc6600;")
        else:
            self._card_hint.setText(
                f"{result.card.display_name} connected. For a message addressed to it, "
                "type the card PIN below instead of a passphrase, then touch the token "
                "if it asks."
            )
            self._card_hint.setStyleSheet("color: #006600;")
        self._card_hint.show()
        self._passphrase_label.setText("Passphrase or card PIN:")
        self._passphrase.setPlaceholderText("Passphrase for the private key, or the card PIN…")

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        self._vm.refresh_card()
        self._refresh_token_button()

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
        # Pass the field's text accessor; the viewmodel reads it synchronously
        # on the UI thread before the worker starts, so no plaintext copy
        # lingers in a closure.
        self._vm.submit(self._passphrase.text)
        self._passphrase.clear()
