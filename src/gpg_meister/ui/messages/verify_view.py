"""Verify-tab view (planv2.md §4.8)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.message import VerifyResult
from gpg_meister.ui.messages.verify_viewmodel import VerifyViewModel


class VerifyView(QWidget):
    """Verify tab: paste message + optional detached signature, show result."""

    def __init__(self, viewmodel: VerifyViewModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vm = viewmodel
        self._build_ui()
        self._connect_signals()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        layout.addWidget(QLabel("Signed message or clearsigned block:"))
        self._data = QTextEdit()
        self._data.setPlaceholderText(
            "Paste the signed message or -----BEGIN PGP SIGNED MESSAGE----- block…"
        )
        self._data.setAcceptRichText(False)
        layout.addWidget(self._data, stretch=1)

        sig_box = QGroupBox("Detached signature (leave empty for clearsigned messages)")
        sig_layout = QVBoxLayout(sig_box)
        self._signature = QTextEdit()
        self._signature.setMaximumHeight(80)
        self._signature.setPlaceholderText("Paste -----BEGIN PGP SIGNATURE----- block here…")
        self._signature.setAcceptRichText(False)
        sig_layout.addWidget(self._signature)
        layout.addWidget(sig_box)

        btn_row = QHBoxLayout()
        self._btn_verify = QPushButton("Verify")
        self._btn_verify.setEnabled(False)
        self._btn_clear = QPushButton("Clear")
        btn_row.addWidget(self._btn_verify)
        btn_row.addWidget(self._btn_clear)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedHeight(4)
        self._progress.hide()
        layout.addWidget(self._progress)

        self._error_label = QLabel()
        self._error_label.setStyleSheet("color: #cc0000;")
        self._error_label.setWordWrap(True)
        self._error_label.hide()
        layout.addWidget(self._error_label)

        self._result_label = QLabel()
        self._result_label.setWordWrap(True)
        self._result_label.hide()
        layout.addWidget(self._result_label)

    def _connect_signals(self) -> None:
        self._vm.loading_changed.connect(self._on_loading)
        self._vm.operation_succeeded.connect(self._on_success)
        self._vm.operation_failed.connect(self._on_error)

        self._data.textChanged.connect(self._on_data_changed)
        self._signature.textChanged.connect(
            lambda: self._vm.set_signature(self._signature.toPlainText())
        )
        self._btn_verify.clicked.connect(self._vm.submit)
        self._btn_clear.clicked.connect(self._clear)

    def _on_data_changed(self) -> None:
        self._vm.set_data(self._data.toPlainText())
        self._btn_verify.setEnabled(self._vm.can_submit())

    def _on_loading(self, loading: bool) -> None:
        if loading:
            self._progress.show()
        else:
            self._progress.hide()
        self._btn_verify.setEnabled(not loading and self._vm.can_submit())

    def _on_success(self, result: object) -> None:
        if not isinstance(result, VerifyResult):
            return
        self._error_label.hide()
        if result.signature_valid:
            from gpg_meister.models.key_info import TrustLevel
            signer = result.signer_fingerprint or "unknown"
            date_str = (
                result.signed_at.strftime("%Y-%m-%d %H:%M UTC")
                if result.signed_at
                else "unknown date"
            )
            trust = result.signer_trust
            trust_line = f"\nSigner trust: {trust.value}"
            untrusted = trust in (TrustLevel.UNKNOWN, TrustLevel.NEVER)
            if untrusted:
                trust_line += "  ⚠ Signer is not in your trust web — identity unverified"
            self._result_label.setText(
                f"Signature VALID\nSigner: {signer}\nSigned at: {date_str}{trust_line}"
            )
            color = "#cc6600" if untrusted else "#006600"
            self._result_label.setStyleSheet(f"color: {color}; font-weight: bold;")
        else:
            from gpg_meister.models.message import SignatureStatus
            messages = {
                SignatureStatus.INVALID: (
                    "Signature INVALID — the message may have been tampered with."
                ),
                SignatureStatus.REVOKED_KEY: (
                    "Signature rejected — the signing key has been REVOKED."
                ),
                SignatureStatus.EXPIRED_KEY: (
                    "Signature rejected — the signing key has EXPIRED."
                ),
                SignatureStatus.EXPIRED_SIG: (
                    "Signature rejected — the signature itself has EXPIRED."
                ),
                SignatureStatus.ERROR: (
                    "Signature could not be verified — the public key may be missing."
                ),
                SignatureStatus.NONE: "No signature was found in the supplied data.",
            }
            self._result_label.setText(
                messages.get(result.signature_status, "Signature INVALID.")
            )
            self._result_label.setStyleSheet("color: #cc0000; font-weight: bold;")
        self._result_label.show()

    def _on_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.show()
        self._result_label.hide()

    def _clear(self) -> None:
        self._data.clear()
        self._signature.clear()
        self._result_label.hide()
        self._error_label.hide()
