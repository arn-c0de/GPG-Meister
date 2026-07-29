"""Dialogs for the destructive card operations: PINs, keytocard, on-card keygen.

Each dialog does one job, runs it on a worker thread, and reports the outcome in
place. The shared base holds the parts that matter for safety rather than
layout: secrets are moved into ``SecureBytes`` on the UI thread and the input
fields cleared before the worker starts, and every action that can destroy key
material is gated behind a typed confirmation.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QThreadPool, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.key_info import KeyInfo
from gpg_meister.models.smartcard import CardInfo, CardPin, CardSlot
from gpg_meister.security.secure_bytes import SecureBytes, _zero_bytes_object
from gpg_meister.services.key_service import KeyService
from gpg_meister.services.smartcard_service import SmartcardService
from gpg_meister.ui.qt_helpers import busy_bar, error_label
from gpg_meister.ui.widgets.passphrase_field import PassphraseField
from gpg_meister.ui.worker import Worker


def secure_from_field(field: PassphraseField) -> SecureBytes:
    """Move a PIN out of a widget into a wiped-on-close buffer.

    Card PINs are taken verbatim — no Unicode normalisation — because the card
    compares the bytes it was programmed with, and a mangled PIN would cost one
    of the few attempts before the card locks itself.
    """
    raw = field.text().encode("utf-8")
    secure = SecureBytes.from_bytes(raw)
    _zero_bytes_object(raw)
    return secure


class _CardActionDialog(QDialog):
    """Base for the card dialogs: a form, a run button, and a result line."""

    completed: Signal = Signal()

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(460)
        self._pool = QThreadPool.globalInstance()
        self._layout = QVBoxLayout(self)
        self._form = QFormLayout()
        self._form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        self._layout.addLayout(self._form)

    def _finish_ui(self, *, action_text: str) -> None:
        self._progress = busy_bar()
        self._layout.addWidget(self._progress)
        self._error_label = error_label()
        self._layout.addWidget(self._error_label)
        self._status_label = QLabel()
        self._status_label.setWordWrap(True)
        self._status_label.hide()
        self._layout.addWidget(self._status_label)

        self._btn_run = QPushButton(action_text)
        self._btn_run.clicked.connect(self._submit)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.addButton(self._btn_run, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.rejected.connect(self.reject)
        self._layout.addWidget(buttons)

    def _add_note(self, text: str, *, style: str = "color: #666666;") -> None:
        label = QLabel(text)
        label.setWordWrap(True)
        label.setStyleSheet(style)
        self._layout.addWidget(label)

    def _confirm_typed(self, word: str, question: str) -> bool:
        """Require the user to type ``word`` before something irreversible."""
        answer, ok = QInputDialog.getText(self, self.windowTitle(), question)
        return ok and answer.strip().upper() == word

    def _run(self, work: Callable[[], None], *, success: str) -> None:
        self._error_label.hide()
        self._status_label.hide()
        self._progress.setVisible(True)
        self._btn_run.setEnabled(False)

        worker = Worker(work)
        worker.signals.result.connect(lambda _result: self._on_success(success))
        worker.signals.error.connect(self._on_error)
        worker.signals.finished.connect(self._on_finished)
        self._pool.start(worker)

    def _on_success(self, message: str) -> None:
        self._status_label.setText(message)
        self._status_label.setStyleSheet("color: #006600;")
        self._status_label.show()
        self.completed.emit()

    def _on_error(self, message: str) -> None:
        self._error_label.setText(message)
        self._error_label.show()

    def _on_finished(self) -> None:
        self._progress.setVisible(False)
        self._btn_run.setEnabled(True)

    def _submit(self) -> None:  # pragma: no cover - overridden
        raise NotImplementedError


class ChangePinDialog(_CardActionDialog):
    """Change the user or admin PIN, or unblock a locked user PIN."""

    _MODE_USER = "Change user PIN"
    _MODE_ADMIN = "Change admin PIN"
    _MODE_UNBLOCK = "Unblock user PIN (with admin PIN)"

    def __init__(
        self,
        service: SmartcardService,
        card: CardInfo | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__("Card PIN", parent)
        self._svc = service
        self._card = card

        self._mode = QComboBox()
        self._mode.addItems([self._MODE_USER, self._MODE_ADMIN, self._MODE_UNBLOCK])
        self._mode.currentIndexChanged.connect(lambda _i: self._update_labels())
        self._form.addRow("Action:", self._mode)

        self._current = PassphraseField(show_strength=False)
        self._new = PassphraseField(show_strength=False)
        self._confirm = PassphraseField(show_strength=False)
        self._current_label = QLabel("Current PIN:")
        self._form.addRow(self._current_label, self._current)
        self._form.addRow("New PIN:", self._new)
        self._form.addRow("Repeat new PIN:", self._confirm)

        if card is not None:
            attempts, _style = _attempts_text(card)
            self._add_note(f"Attempts left before the card locks itself — {attempts}")
        self._add_note(
            "A wrong PIN costs one attempt. When the user PIN runs out, unblock it with "
            "the admin PIN; when the admin PIN runs out, the card can only be factory "
            "reset, which destroys the keys on it.",
            style="color: #cc6600;",
        )
        self._finish_ui(action_text="Change PIN")
        self._update_labels()

    def _update_labels(self) -> None:
        unblocking = self._mode.currentText() == self._MODE_UNBLOCK
        self._current_label.setText("Admin PIN:" if unblocking else "Current PIN:")
        self._btn_run.setText("Unblock PIN" if unblocking else "Change PIN")

    def _submit(self) -> None:
        if self._new.text() != self._confirm.text():
            self._on_error("The new PIN and its repetition do not match.")
            return
        if not self._new.text() or not self._current.text():
            self._on_error("Both fields are required.")
            return

        mode = self._mode.currentText()
        current = secure_from_field(self._current)
        new = secure_from_field(self._new)
        self._current.clear()
        self._new.clear()
        self._confirm.clear()
        service = self._svc

        def _work() -> None:
            with current as old_pin, new as new_pin:
                if mode == self._MODE_UNBLOCK:
                    service.unblock_user_pin(admin_pin=old_pin, new_user_pin=new_pin)
                else:
                    pin = CardPin.ADMIN if mode == self._MODE_ADMIN else CardPin.USER
                    service.change_pin(pin, current=old_pin, new=new_pin)

        self._run(_work, success="The card accepted the new PIN.")


class MoveKeyToCardDialog(_CardActionDialog):
    """Move a local private key onto the card. Irreversible."""

    def __init__(
        self,
        service: SmartcardService,
        key_service: KeyService,
        card: CardInfo | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__("Move key to card", parent)
        self._svc = service
        self._key_svc = key_service
        self._card = card

        self._key_combo = QComboBox()
        self._key_combo.currentIndexChanged.connect(lambda _i: self._reload_parts())
        self._form.addRow("Key:", self._key_combo)
        self._part_combo = QComboBox()
        self._form.addRow("Which part:", self._part_combo)
        self._slot_combo = QComboBox()
        for slot in CardSlot:
            # Store the plain value: Qt hands a StrEnum back as a bare str, so
            # keeping the enum object here would fail every isinstance check.
            self._slot_combo.addItem(_slot_label(slot, card), slot.value)
        self._form.addRow("Card slot:", self._slot_combo)

        self._passphrase = PassphraseField(show_strength=False)
        self._passphrase.setPlaceholderText("Passphrase of the key being moved…")
        self._form.addRow("Key passphrase:", self._passphrase)
        self._admin_pin = PassphraseField(show_strength=False)
        self._admin_pin.setPlaceholderText("Admin PIN of the card…")
        self._form.addRow("Admin PIN:", self._admin_pin)

        self._add_note(
            "This moves the private key onto the card and replaces the copy on this "
            "computer with a pointer to it. The key cannot be copied back off the card. "
            "Make a vault backup first if you do not have one.",
            style="color: #cc0000; font-weight: bold;",
        )
        self._finish_ui(action_text="Move key to card")
        self._load_keys()

    def _load_keys(self) -> None:
        def _list() -> list[KeyInfo]:
            return [
                key
                for key in self._key_svc.list_keys()
                if key.has_private_key and not key.is_stub
            ]

        worker = Worker(_list)
        worker.signals.result.connect(self._on_keys)
        worker.signals.error.connect(self._on_error)
        self._pool.start(worker)

    def _on_keys(self, keys: object) -> None:
        if not isinstance(keys, list):
            return
        self._key_combo.clear()
        for key in keys:
            if isinstance(key, KeyInfo):
                self._key_combo.addItem(key.display_label, key)
        self._reload_parts()

    def _reload_parts(self) -> None:
        self._part_combo.clear()
        key = self._key_combo.currentData()
        if not isinstance(key, KeyInfo):
            return
        self._part_combo.addItem(f"Primary key  [{key.short_fingerprint}]", 0)
        for index, fingerprint in enumerate(key.subkey_fingerprints, start=1):
            self._part_combo.addItem(f"Subkey {index}  [{fingerprint[-16:]}]", index)

    def _submit(self) -> None:
        key = self._key_combo.currentData()
        part = self._part_combo.currentData()
        slot = _slot_from_data(self._slot_combo.currentData())
        if not isinstance(key, KeyInfo) or slot is None:
            self._on_error("Choose a key and a card slot first.")
            return
        if not self._admin_pin.text():
            self._on_error("The card's admin PIN is required.")
            return

        occupied = self._card.slot_fingerprint(slot) if self._card else ""
        if occupied and not self._confirm_typed(
            "REPLACE",
            f"The {slot.slot_name.lower()} slot already holds {occupied[-16:]}.\n"
            "Moving a key there destroys it.\n\nType REPLACE to continue.",
        ):
            return
        if not self._confirm_typed(
            "MOVE",
            f"Move {key.primary_user_id} onto {_card_name(self._card)}?\n"
            "The private key will no longer be stored on this computer.\n\n"
            "Type MOVE to continue.",
        ):
            return

        passphrase = secure_from_field(self._passphrase)
        admin_pin = secure_from_field(self._admin_pin)
        self._passphrase.clear()
        self._admin_pin.clear()
        service = self._svc
        fingerprint = key.fingerprint
        key_index = int(part) if isinstance(part, int) else 0
        allow_overwrite = bool(occupied)

        def _work() -> None:
            with passphrase as key_pw, admin_pin as pin:
                service.move_key_to_card(
                    fingerprint,
                    slot,
                    key_passphrase=key_pw,
                    admin_pin=pin,
                    key_index=key_index,
                    allow_overwrite=allow_overwrite,
                )

        self._run(_work, success="The key now lives on the card.")


class GenerateOnCardDialog(_CardActionDialog):
    """Generate a fresh key set on the card itself."""

    def __init__(
        self,
        service: SmartcardService,
        card: CardInfo | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__("Generate keys on card", parent)
        self._svc = service
        self._card = card

        self._name = QLineEdit()
        self._name.setPlaceholderText("Full name")
        self._email = QLineEdit()
        self._email.setPlaceholderText("name@example.org")
        self._expiry = QComboBox()
        for label, value in (
            ("Does not expire", "0"),
            ("1 year", "1y"),
            ("2 years", "2y"),
            ("5 years", "5y"),
        ):
            self._expiry.addItem(label, value)
        self._form.addRow("Name:", self._name)
        self._form.addRow("Email:", self._email)
        self._form.addRow("Expires:", self._expiry)

        self._admin_pin = PassphraseField(show_strength=False)
        self._admin_pin.setPlaceholderText("Admin PIN of the card…")
        self._form.addRow("Admin PIN:", self._admin_pin)
        self._user_pin = PassphraseField(show_strength=False)
        self._user_pin.setPlaceholderText("PIN of the card…")
        self._form.addRow("Card PIN:", self._user_pin)

        self._backup = QCheckBox("Keep an off-card backup of the encryption key (recommended)")
        self._backup.setChecked(True)
        self._layout.addWidget(self._backup)
        self._add_note(
            "Keys generated on the card can never be read off it. Without the off-card "
            "backup of the encryption key, a lost or broken card means everything "
            "encrypted to it is unreadable for good.",
            style="color: #cc6600;",
        )
        self._finish_ui(action_text="Generate on card")

    def _submit(self) -> None:
        if not self._name.text().strip() or not self._email.text().strip():
            self._on_error("Name and email are required.")
            return
        if not self._admin_pin.text() or not self._user_pin.text():
            self._on_error("Both the admin PIN and the card PIN are required.")
            return

        occupied = self._card.occupied_slots() if self._card else ()
        if occupied and not self._confirm_typed(
            "REPLACE",
            f"{_card_name(self._card)} already holds "
            f"{len(occupied)} key(s). Generating new ones destroys them, and anything "
            "encrypted to them becomes unreadable.\n\nType REPLACE to continue.",
        ):
            return

        admin_pin = secure_from_field(self._admin_pin)
        user_pin = secure_from_field(self._user_pin)
        self._admin_pin.clear()
        self._user_pin.clear()
        service = self._svc
        name = self._name.text().strip()
        email = self._email.text().strip()
        expiry = str(self._expiry.currentData())
        backup = self._backup.isChecked()
        allow_overwrite = bool(occupied)

        def _work() -> None:
            with admin_pin as admin, user_pin as user:
                service.generate_key_on_card(
                    admin_pin=admin,
                    user_pin=user,
                    name=name,
                    email=email,
                    expiry=expiry,
                    off_card_backup=backup,
                    allow_overwrite=allow_overwrite,
                )

        self._run(_work, success="The card generated its keys.")


def _attempts_text(card: CardInfo) -> tuple[str, str]:
    user, _reset, admin = card.pin_retries
    if user < 0:
        return "not reported by this card", "color: #666666;"
    return f"user PIN: {user}, admin PIN: {admin}", "color: #666666;"


def _slot_from_data(data: object) -> CardSlot | None:
    """Rebuild the slot enum from what Qt stored as combo-box item data."""
    if isinstance(data, CardSlot):
        return data
    if isinstance(data, str):
        try:
            return CardSlot(data)
        except ValueError:
            return None
    return None


def _card_name(card: CardInfo | None) -> str:
    return card.display_name if card is not None else "the card"


def _slot_label(slot: CardSlot, card: CardInfo | None) -> str:
    occupied = card.slot_fingerprint(slot) if card else ""
    if occupied:
        return f"{slot.slot_name} — occupied by {occupied[-16:]}"
    return f"{slot.slot_name} — empty"
