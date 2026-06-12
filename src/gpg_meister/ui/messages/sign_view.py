"""Sign-tab view (planv2.md §4.8)."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.models.message import SignResult
from gpg_meister.ui.messages.sign_viewmodel import SignViewModel
from gpg_meister.ui.qt_helpers import busy_bar, error_label
from gpg_meister.ui.widgets.passphrase_field import PassphraseField


class SignView(QWidget):
    """Sign tab: select key, enter message, produce detached or clearsign."""

    def __init__(self, viewmodel: SignViewModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._vm = viewmodel
        self._build_ui()
        self._connect_signals()
        self._vm.load_keys()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        key_row = QHBoxLayout()
        key_row.addWidget(QLabel("Signing key:"))
        self._key_combo = QComboBox()
        self._key_combo.setPlaceholderText("Select private key…")
        self._key_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        key_row.addWidget(self._key_combo, stretch=1)
        layout.addLayout(key_row)

        layout.addWidget(QLabel("Passphrase:"))
        self._passphrase = PassphraseField(show_strength=False)
        self._passphrase.setPlaceholderText("Passphrase for the signing key…")
        layout.addWidget(self._passphrase)

        layout.addWidget(QLabel("Message to sign:"))
        self._data = QTextEdit()
        self._data.setPlaceholderText("Paste or type the message to sign…")
        self._data.setAcceptRichText(False)
        layout.addWidget(self._data, stretch=1)

        self._detached_check = QCheckBox("Produce detached signature (armored .asc)")
        self._detached_check.setChecked(True)
        layout.addWidget(self._detached_check)

        btn_row = QHBoxLayout()
        self._btn_sign = QPushButton("Sign")
        self._btn_sign.setEnabled(False)
        self._btn_clear = QPushButton("Clear")
        btn_row.addWidget(self._btn_sign)
        btn_row.addWidget(self._btn_clear)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._progress = busy_bar()
        layout.addWidget(self._progress)

        self._error_label = error_label()
        layout.addWidget(self._error_label)

        output_box = QGroupBox("Signature output")
        output_layout = QVBoxLayout(output_box)
        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setPlaceholderText("Armored signature will appear here…")
        self._btn_copy = QPushButton("Copy to Clipboard")
        self._btn_copy.setEnabled(False)
        output_layout.addWidget(self._output, stretch=1)
        output_layout.addWidget(self._btn_copy)
        layout.addWidget(output_box, stretch=1)

    def _connect_signals(self) -> None:
        self._vm.keys_loaded.connect(self._on_keys_loaded)
        self._vm.loading_changed.connect(self._on_loading)
        self._vm.operation_succeeded.connect(self._on_success)
        self._vm.operation_failed.connect(self._on_error)

        self._key_combo.currentIndexChanged.connect(self._on_key_changed)
        self._passphrase.passphrase_changed.connect(self._on_passphrase_changed)
        self._data.textChanged.connect(self._on_data_changed)
        self._detached_check.toggled.connect(self._vm.set_detached)
        self._btn_sign.clicked.connect(self._submit)
        self._btn_clear.clicked.connect(self._clear)
        self._btn_copy.clicked.connect(self._copy_output)

    def _on_keys_loaded(self, keys: list[KeyInfo]) -> None:
        self._key_combo.clear()
        for key in keys:
            self._key_combo.addItem(key.display_label, key)

    def _on_key_changed(self, idx: int) -> None:
        key = self._key_combo.itemData(idx)
        self._vm.set_fingerprint(key.fingerprint if isinstance(key, KeyInfo) else "")
        self._update_button()

    def _on_passphrase_changed(self) -> None:
        self._vm.set_passphrase_non_empty(bool(self._passphrase.text()))
        self._update_button()

    def _on_data_changed(self) -> None:
        self._vm.set_data(self._data.toPlainText())
        self._update_button()

    def _update_button(self) -> None:
        self._btn_sign.setEnabled(self._vm.can_submit())

    def _on_loading(self, loading: bool) -> None:
        self._progress.setVisible(loading)
        self._btn_sign.setEnabled(not loading and self._vm.can_submit())

    def _on_success(self, result: object) -> None:
        if not isinstance(result, SignResult):
            return
        self._error_label.hide()
        self._output.setPlainText(result.armored_signature)
        self._btn_copy.setEnabled(True)

    def _on_error(self, msg: str) -> None:
        self._error_label.setText(msg)
        self._error_label.show()

    def _clear(self) -> None:
        self._data.clear()
        self._passphrase.clear()
        self._output.clear()
        self._error_label.hide()
        self._btn_copy.setEnabled(False)

    def _copy_output(self) -> None:
        text = self._output.toPlainText()
        if text:
            from gpg_meister.ui.clipboard import copy_text

            copy_text(text)

    def _submit(self) -> None:
        # Pass the field's text accessor; the viewmodel reads it synchronously
        # on the UI thread before the worker starts, so no plaintext copy
        # lingers in a closure.
        self._vm.submit(self._passphrase.text)
        self._passphrase.clear()
