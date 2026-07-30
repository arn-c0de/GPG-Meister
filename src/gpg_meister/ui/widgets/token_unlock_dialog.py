"""Ask a hardware token for a key's passphrase: PIN, touch, done.

Wherever the application would normally put a passphrase field, a key enrolled
with a security key gets this dialog instead. It hands back a ``SecureBytes``
holding the key's real passphrase, so every caller downstream is unchanged —
the same buffer, through the same pipe, to the same ``--passphrase-fd``.

Two properties matter more than the layout:

- **The derivation runs on a worker thread.** Touching the token blocks for up
  to thirty seconds. On the UI thread that is a frozen window, and a user who
  concludes the app has hung will unplug the token mid-operation.
- **The PIN never survives the attempt.** It is moved into a ``SecureBytes`` and
  the field is cleared before the worker starts, so a dialog left open after a
  failure holds nothing worth reading out of memory.
"""

from __future__ import annotations

from PySide6.QtCore import QThreadPool, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object
from gpg_meister.services.key_unlock_service import KeyUnlockService
from gpg_meister.ui.qt_helpers import busy_bar, error_label
from gpg_meister.ui.widgets.passphrase_field import PassphraseField
from gpg_meister.ui.worker import Worker

_TOUCH_HINT = "Touch your security key now — it is waiting and will time out."
_IDLE_HINT = "Enter the PIN of your security key, then touch it when asked."


def secure_pin_from(field: PassphraseField) -> SecureBytes:
    """Move a PIN out of a widget, verbatim.

    No Unicode normalisation: the token compares the bytes its PIN was set with,
    and an altered PIN would spend one of the handful of attempts it allows
    before locking itself.
    """
    raw = field.text().encode("utf-8")
    try:
        return SecureBytes.from_bytes(raw)
    finally:
        _zero_bytes_object(raw)


class TokenUnlockDialog(QDialog):
    """Derive a key's passphrase from an enrolled security key.

    On ``accepted`` the passphrase is available from :meth:`take_secret`, which
    transfers ownership to the caller — the dialog holds nothing afterwards.
    """

    unlocked: Signal = Signal()

    def __init__(
        self,
        unlock: KeyUnlockService,
        keys: list[KeyInfo],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        if not keys:
            raise ValueError("no token-backed key was offered to the unlock dialog")
        self.setWindowTitle("Unlock with security key")
        self.setMinimumWidth(460)
        self._unlock = unlock
        self._keys = keys
        self._pool = QThreadPool.globalInstance()
        self._secret: SecureBytes | None = None
        self._build_ui()

    # ------------------------------------------------------------------ layout

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()

        self._key_picker = QComboBox()
        for key in self._keys:
            self._key_picker.addItem(self._describe(key), key.fingerprint)
        # With a single enrolled key there is nothing to choose, and a
        # one-entry dropdown only invites the user to look for alternatives.
        self._key_picker.setVisible(len(self._keys) > 1)
        if len(self._keys) > 1:
            form.addRow("Key:", self._key_picker)

        self._pin = PassphraseField(show_strength=False)
        self._pin.setPlaceholderText("PIN of your security key…")
        form.addRow("PIN:", self._pin)
        layout.addLayout(form)

        self._hint = QLabel(_IDLE_HINT)
        self._hint.setWordWrap(True)
        layout.addWidget(self._hint)

        self._busy = busy_bar()
        self._busy.setVisible(False)
        layout.addWidget(self._busy)

        self._error = error_label()
        self._error.setVisible(False)
        layout.addWidget(self._error)

        self._buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self._ok = self._buttons.button(QDialogButtonBox.StandardButton.Ok)
        self._ok.setText("Unlock")
        self._ok.setEnabled(False)
        self._buttons.accepted.connect(self._start)
        self._buttons.rejected.connect(self.reject)
        layout.addWidget(self._buttons)

        self._pin.passphrase_changed.connect(self._update_ok)

    @staticmethod
    def _describe(key: KeyInfo) -> str:
        return f"{key.primary_user_id} · {key.fingerprint[-16:]}"

    def _update_ok(self) -> None:
        self._ok.setEnabled(bool(self._pin.text()))

    # ------------------------------------------------------------------- action

    def _selected_fingerprint(self) -> str:
        if len(self._keys) == 1:
            return self._keys[0].fingerprint
        return str(self._key_picker.currentData())

    def _start(self) -> None:
        if not self._pin.text():
            return
        fingerprint = self._selected_fingerprint()
        pin = secure_pin_from(self._pin)
        # Cleared before the worker runs: the attempt owns the PIN from here.
        self._pin.clear()
        self._set_running(True)

        def _derive() -> SecureBytes:
            with pin:
                return self._unlock.unlock_with_token(
                    fingerprint, pin=pin, on_touch=self._on_touch_requested
                )

        worker = Worker(_derive)
        worker.signals.result.connect(self._on_result)
        worker.signals.error.connect(self._on_error)
        self._pool.start(worker)

    def _on_touch_requested(self) -> None:
        # Called from the worker thread; Qt queues the change onto the UI thread.
        self._hint.setText(_TOUCH_HINT)

    def _set_running(self, running: bool) -> None:
        self._busy.setVisible(running)
        self._ok.setEnabled(not running and bool(self._pin.text()))
        self._buttons.button(QDialogButtonBox.StandardButton.Cancel).setEnabled(not running)
        if running:
            self._error.setVisible(False)

    def _on_result(self, secret: object) -> None:
        self._set_running(False)
        if not isinstance(secret, SecureBytes):  # pragma: no cover - worker contract
            self._on_error("The security key returned nothing usable.")
            return
        self._secret = secret
        self.unlocked.emit()
        self.accept()

    def _on_error(self, message: str) -> None:
        self._set_running(False)
        self._hint.setText(_IDLE_HINT)
        self._error.setText(message)
        self._error.setVisible(True)

    # ------------------------------------------------------------------ result

    def take_secret(self) -> SecureBytes | None:
        """Hand the passphrase to the caller, who then owns and closes it."""
        secret, self._secret = self._secret, None
        return secret

    def closeEvent(self, event: object) -> None:
        # A secret nobody collected must not outlive the dialog.
        if self._secret is not None:
            self._secret.close()
            self._secret = None
        super().closeEvent(event)  # type: ignore[arg-type]


def token_backed_keys(unlock: KeyUnlockService, keys: list[KeyInfo]) -> list[KeyInfo]:
    """The subset of ``keys`` that a security key can unlock."""
    return [key for key in keys if unlock.methods_for(key.fingerprint).has_token]
