"""Smartcard panel — inspect the inserted YubiKey / OpenPGP token (Keys tab).

Shows what GnuPG sees on the card (device, serial, cardholder, PIN attempts
left, the keys in its three slots) and lets the user link those keys into GPG
Meister's own keyring. Linking is the step that makes decrypt/sign work: the
app runs GnuPG against a private ``--homedir``, so the card's secret-key stubs
have to be created there once per card.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt, QThreadPool, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gpg_meister.models.smartcard import CardInfo
from gpg_meister.services.key_service import KeyService
from gpg_meister.services.smartcard_service import CardSyncResult, SmartcardService
from gpg_meister.ui.qt_helpers import busy_bar, error_label, monospace_font
from gpg_meister.ui.worker import Worker

_SLOT_NAMES = ("Signature key", "Encryption key", "Authentication key")

_COLOR_OK = "color: #006600;"
_COLOR_WARN = "color: #cc6600;"
_COLOR_MUTED = "color: #666666;"


def _plain_label(text: str, *, style: str = "") -> QLabel:
    """A selectable label that never interprets card-supplied text as markup."""
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(
        Qt.TextInteractionFlag.TextSelectableByMouse
        | Qt.TextInteractionFlag.TextSelectableByKeyboard
    )
    label.setWordWrap(True)
    if style:
        label.setStyleSheet(style)
    return label


def _retries_text(card: CardInfo) -> tuple[str, str]:
    user, _reset, admin = card.pin_retries
    if user < 0:
        return "not reported by this card", _COLOR_MUTED
    if user == 0:
        return "0 — the PIN is blocked; unblock it with the admin PIN", "color: #cc0000;"
    admin_part = f", admin PIN: {admin}" if admin >= 0 else ""
    style = _COLOR_OK if user > 1 else _COLOR_WARN
    return f"{user} attempt(s) left{admin_part}", style


class SmartcardDialog(QDialog):
    """Card status, PIN counters, and the "link card keys" action."""

    keyring_changed: Signal = Signal()

    def __init__(
        self,
        smartcard: SmartcardService,
        key_service: KeyService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Smartcard / YubiKey")
        self.setMinimumWidth(560)
        self._svc = smartcard
        self._key_svc = key_service
        self._pool = QThreadPool.globalInstance()
        self._last_result: CardSyncResult | None = None
        self._build_ui()
        self.refresh()

    # ---------------------------------------------------------------------- ui

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)

        self._headline = _plain_label("Looking for a smartcard…")
        self._headline.setStyleSheet("font-weight: bold;")
        layout.addWidget(self._headline)

        self._details_box = QGroupBox("Card")
        self._details_form = QFormLayout(self._details_box)
        self._details_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
        layout.addWidget(self._details_box)

        self._keys_box = QGroupBox("Keys on the card")
        self._keys_layout = QVBoxLayout(self._keys_box)
        layout.addWidget(self._keys_box)

        self._hint = _plain_label(
            "Keys stored on a token never leave it. When a message needs such a key, "
            "enter the card PIN where GPG Meister asks for a passphrase, and touch the "
            "token if it requires confirmation.",
            style=_COLOR_MUTED,
        )
        layout.addWidget(self._hint)

        self._progress = busy_bar()
        layout.addWidget(self._progress)
        self._error_label = error_label()
        layout.addWidget(self._error_label)

        button_row = QHBoxLayout()
        self._btn_refresh = QPushButton("Refresh")
        self._btn_refresh.clicked.connect(self.refresh)
        self._btn_link = QPushButton("Link card keys")
        self._btn_link.setToolTip(
            "Let GnuPG learn the inserted card so its keys become usable in this app."
        )
        self._btn_link.clicked.connect(self._link_keys)
        self._btn_import = QPushButton("Import public key…")
        self._btn_import.setEnabled(False)
        self._btn_import.clicked.connect(self._open_import_dialog)
        self._btn_import.setVisible(self._key_svc is not None)
        button_row.addWidget(self._btn_refresh)
        button_row.addWidget(self._btn_link)
        button_row.addWidget(self._btn_import)
        button_row.addStretch()
        layout.addLayout(button_row)

        # Everything that writes to the card. Disabled until one is detected,
        # since all of it needs a card present to mean anything.
        admin_row = QHBoxLayout()
        self._btn_pin = QPushButton("PIN…")
        self._btn_pin.setToolTip("Change the user or admin PIN, or unblock a locked PIN")
        self._btn_pin.clicked.connect(self._open_pin_dialog)
        self._btn_move = QPushButton("Move key to card…")
        self._btn_move.setToolTip("Move a private key from this computer onto the card")
        self._btn_move.clicked.connect(self._open_move_dialog)
        self._btn_move.setVisible(self._key_svc is not None)
        self._btn_generate = QPushButton("Generate on card…")
        self._btn_generate.setToolTip("Create a new key set on the card itself")
        self._btn_generate.clicked.connect(self._open_generate_dialog)
        for button in (self._btn_pin, self._btn_move, self._btn_generate):
            button.setEnabled(False)
            admin_row.addWidget(button)
        admin_row.addStretch()
        layout.addLayout(admin_row)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # ----------------------------------------------------------------- actions

    def refresh(self) -> None:
        self._start(self._svc.sync)

    def _link_keys(self) -> None:
        # Linking *is* the sync call: `gpg --card-status` creates the stubs.
        # Re-running it is the retry path after importing a missing public key.
        self._start(self._svc.sync, notify_keyring=True)

    def _start(
        self, fn: Callable[[], CardSyncResult], *, notify_keyring: bool = False
    ) -> None:
        self._error_label.hide()
        self._progress.setVisible(True)
        self._btn_refresh.setEnabled(False)
        self._btn_link.setEnabled(False)

        worker = Worker(fn)
        worker.signals.result.connect(
            lambda result: self._on_result(result, notify_keyring=notify_keyring)
        )
        worker.signals.error.connect(self._on_error)
        worker.signals.finished.connect(self._on_finished)
        self._pool.start(worker)

    def _open_import_dialog(self) -> None:
        if self._key_svc is None:
            return
        from gpg_meister.ui.keys.public_key_import_view import PublicKeyImportDialog

        dialog = PublicKeyImportDialog(self._key_svc, parent=self)
        dialog.exec()
        self.keyring_changed.emit()
        self._link_keys()

    # ------------------------------------------------------------ card admin

    def _card(self) -> CardInfo | None:
        return self._last_result.card if self._last_result else None

    def _open_pin_dialog(self) -> None:
        from gpg_meister.ui.keys.card_admin_view import ChangePinDialog

        dialog = ChangePinDialog(self._svc, self._card(), parent=self)
        # A PIN change moves the retry counters, which this panel displays.
        dialog.completed.connect(self.refresh)
        dialog.exec()
        self.refresh()

    def _open_move_dialog(self) -> None:
        if self._key_svc is None:
            return
        from gpg_meister.ui.keys.card_admin_view import MoveKeyToCardDialog

        dialog = MoveKeyToCardDialog(self._svc, self._key_svc, self._card(), parent=self)
        # The moved key becomes a stub, so the key list has to be re-read.
        dialog.completed.connect(self.keyring_changed)
        dialog.exec()
        self._link_keys()

    def _open_generate_dialog(self) -> None:
        from gpg_meister.ui.keys.card_admin_view import GenerateOnCardDialog

        dialog = GenerateOnCardDialog(self._svc, self._card(), parent=self)
        dialog.completed.connect(self.keyring_changed)
        dialog.exec()
        self._link_keys()

    # ----------------------------------------------------------------- results

    def _on_result(self, result: object, *, notify_keyring: bool) -> None:
        if not isinstance(result, CardSyncResult):
            return
        self._last_result = result
        self._render(result)
        if notify_keyring:
            self.keyring_changed.emit()

    def _on_error(self, message: str) -> None:
        self._error_label.setText(message)
        self._error_label.show()

    def _on_finished(self) -> None:
        self._progress.setVisible(False)
        self._btn_refresh.setEnabled(True)
        self._btn_link.setEnabled(True)

    # --------------------------------------------------------------- rendering

    def _render(self, result: CardSyncResult) -> None:
        _clear_form(self._details_form)
        _clear_layout(self._keys_layout)

        card = result.card
        for button in (self._btn_pin, self._btn_move, self._btn_generate):
            button.setEnabled(card is not None)
        if card is None:
            self._headline.setText("No smartcard detected")
            self._headline.setStyleSheet(_COLOR_WARN)
            self._details_form.addRow(
                "",
                _plain_label(
                    "Insert your YubiKey or OpenPGP card, then press Refresh. "
                    "If it is plugged in and still not found, check that a smartcard "
                    "daemon (scdaemon / pcscd) is installed and running.",
                    style=_COLOR_MUTED,
                ),
            )
            self._btn_import.setEnabled(False)
            self._render_known_card_keys(result)
            return

        self._headline.setText(f"{card.display_name} connected")
        self._headline.setStyleSheet(_COLOR_OK + " font-weight: bold;")

        self._add_detail("Device:", card.product_name)
        self._add_detail("Serial:", card.short_serial or "—", monospace=True)
        if card.reader:
            self._add_detail("Reader:", card.reader)
        if card.version:
            self._add_detail("Card version:", card.version)
        if card.cardholder:
            self._add_detail("Cardholder:", card.cardholder)
        if card.url:
            self._add_detail("Public key URL:", card.url)
        retries_text, retries_style = _retries_text(card)
        self._add_detail("PIN attempts:", retries_text, style=retries_style)

        self._render_slots(result, card)
        self._btn_import.setEnabled(bool(self._key_svc) and result.needs_public_key_import)

    def _add_detail(
        self, caption: str, value: str, *, style: str = "", monospace: bool = False
    ) -> None:
        label = _plain_label(value, style=style)
        if monospace:
            label.setFont(monospace_font())
        self._details_form.addRow(caption, label)

    def _render_slots(self, result: CardSyncResult, card: CardInfo) -> None:
        linked = set(result.linked_fingerprints)
        empty = True
        for name, fingerprint in zip(_SLOT_NAMES, card.slot_fingerprints, strict=False):
            if not fingerprint:
                continue
            empty = False
            in_keyring = fingerprint in linked
            status = (
                "usable in GPG Meister"
                if in_keyring
                else "public key missing — import it to use this key"
            )
            row = _plain_label(
                f"{name}: {fingerprint}\n    {status}",
                style=_COLOR_OK if in_keyring else _COLOR_WARN,
            )
            row.setFont(monospace_font())
            self._keys_layout.addWidget(row)

        if empty:
            self._keys_layout.addWidget(
                _plain_label("This card carries no OpenPGP keys yet.", style=_COLOR_MUTED)
            )
        elif result.needs_public_key_import:
            hint = "Import the matching public key, then press “Link card keys”."
            if card.url:
                hint += f" The card points at: {card.url}"
            self._keys_layout.addWidget(_plain_label(hint, style=_COLOR_MUTED))

    def _render_known_card_keys(self, result: CardSyncResult) -> None:
        """With no card inserted, still show which keys are known to need one."""
        if not result.keys:
            self._keys_layout.addWidget(
                _plain_label("No smartcard-backed keys in your keyring.", style=_COLOR_MUTED)
            )
            return
        self._keys_layout.addWidget(
            _plain_label("Keys in your keyring that need a token:", style=_COLOR_MUTED)
        )
        for key in result.keys:
            row = _plain_label(f"{key.storage_label} — {key.display_label}", style=_COLOR_MUTED)
            row.setFont(monospace_font())
            self._keys_layout.addWidget(row)


def _clear_form(form: QFormLayout) -> None:
    while form.rowCount():
        form.removeRow(0)


def _clear_layout(layout: QVBoxLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        if item is None:
            continue
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
