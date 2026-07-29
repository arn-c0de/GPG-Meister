"""Answer scripts for GnuPG's interactive card and key editors.

`gpg --card-edit` and `gpg --edit-key` are menu-driven programs. With
``--command-fd`` they can be driven non-interactively: GnuPG announces each
prompt on the status stream as ``GET_LINE``/``GET_BOOL``/``GET_HIDDEN`` followed
by a *prompt keyword*, and reads the answer from the command pipe.

Answers are therefore keyed by that keyword rather than supplied as a flat list
of lines. That distinction is the safety property of this module: a positional
script that drifts out of step with GnuPG would happily answer "yes" to a
question it never expected — such as "Replace existing keys?" — and destroy key
material. Here, a prompt nobody scripted an answer for has no answer to give, and
the runner aborts the operation instead of guessing.

Some prompts are asked repeatedly with the same keyword (the card menu, or the
three PIN entries of a passphrase change), so every keyword maps to a *queue* of
answers consumed in order. Running the queue dry is treated exactly like an
unknown prompt.

Nothing here talks to GnuPG; :class:`PromptScript` is built by
``smartcard_service`` and executed by ``gpg_service``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from gpg_meister.models.smartcard import CardPin, CardSlot
from gpg_meister.security.secure_bytes import SecureBytes, zero_mutable_buffer

# Prompt keywords GnuPG uses (g10/card-util.c, g10/keyedit.c, g10/keygen.c).
PROMPT_CARD_MENU = "cardedit.prompt"
PROMPT_KEY_MENU = "keyedit.prompt"
PROMPT_PIN_MENU = "cardedit.change_pin.menu"
PROMPT_SLOT = "cardedit.genkeys.storekeytype"
PROMPT_REPLACE_KEYS = "cardedit.genkeys.replace_keys"
PROMPT_BACKUP_ENC = "cardedit.genkeys.backup_enc"
PROMPT_EXPIRY = "keygen.valid"
PROMPT_NAME = "keygen.name"
PROMPT_EMAIL = "keygen.email"
PROMPT_COMMENT = "keygen.comment"
PROMPT_USERID_CMD = "keygen.userid.cmd"
PROMPT_SAVE = "keyedit.save.okay"
PROMPT_USE_PRIMARY = "keyedit.keytocard.use_primary"

# Every keyword GnuPG has used for "type a secret". They share one queue, since
# which of them a given version asks with is exactly what we cannot pin down.
SECRET_PROMPTS: tuple[str, ...] = (
    "passphrase.enter",
    "passphrase.ask",
    "passphrase.pin.ask",
    "passphrase.adminpin.ask",
    "passphrase.resetcode.ask",
)

# Status records that report the outcome of a card operation.
STATUS_OK = "SC_OP_SUCCESS"
STATUS_FAILURE = "SC_OP_FAILURE"

YES = "y"
NO = "n"


class PromptScript:
    """Queued answers for one run of an interactive GnuPG editor.

    Answers are held in ``bytearray``s so :meth:`wipe` can actually clear the
    PINs afterwards; ``str`` and ``bytes`` cannot be zeroed in place.
    """

    def __init__(self) -> None:
        self._queues: dict[str, list[bytearray]] = {}
        self._buffers: list[bytearray] = []

    def add(self, keyword: str, *answers: str | SecureBytes) -> None:
        """Append answers to one prompt's queue."""
        queue = self._queues.setdefault(keyword, [])
        for answer in answers:
            buffer = _to_buffer(answer)
            self._buffers.append(buffer)
            queue.append(buffer)

    def share(self, keywords: Iterable[str], *answers: str | SecureBytes) -> None:
        """Queue answers once but accept them under any of ``keywords``.

        Used for the secret prompts: only one of the aliases will actually be
        asked, and whichever it is must consume from the same ordered queue.
        """
        keywords = list(keywords)
        if not keywords:
            return
        first = keywords[0]
        self.add(first, *answers)
        shared = self._queues[first]
        for keyword in keywords[1:]:
            self._queues[keyword] = shared

    def take(self, keyword: str) -> bytes | None:
        """Pop the next answer for ``keyword``; ``None`` if there is none left."""
        queue = self._queues.get(keyword)
        if not queue:
            return None
        return bytes(queue.pop(0))

    def pending(self) -> dict[str, int]:
        """Remaining answers per keyword — a non-empty result means the run
        ended earlier than the script expected."""
        return {keyword: len(queue) for keyword, queue in self._queues.items() if queue}

    def wipe(self) -> None:
        """Zero every queued answer, including the ones already consumed."""
        for buffer in self._buffers:
            zero_mutable_buffer(buffer)
        self._buffers.clear()
        self._queues.clear()


def _to_buffer(answer: str | SecureBytes) -> bytearray:
    if isinstance(answer, SecureBytes):
        return bytearray(answer.view())
    return bytearray(answer.encode("utf-8"))


def _reject_control_characters(value: SecureBytes, *, what: str) -> None:
    """A newline in a PIN would end the line early and desynchronise the run."""
    view = value.view()
    try:
        if any(byte in (0x00, 0x0A, 0x0D) for byte in view):
            raise ValueError(f"{what} must not contain NUL or newline characters")
        if len(view) == 0:
            raise ValueError(f"{what} must not be empty")
    finally:
        view.release()


def change_pin_script(
    pin: CardPin,
    *,
    current: SecureBytes,
    new: SecureBytes,
) -> PromptScript:
    """Change the user or admin PIN of the inserted card."""
    _reject_control_characters(current, what="the current PIN")
    _reject_control_characters(new, what="the new PIN")

    script = PromptScript()
    script.add(PROMPT_CARD_MENU, "admin", "passwd", "quit")
    # Submenu: 1 = change user PIN, 2 = unblock, 3 = change admin PIN, Q = back.
    script.add(PROMPT_PIN_MENU, "1" if pin is CardPin.USER else "3", "Q")
    # Current PIN, then the new one twice for GnuPG's confirmation prompt.
    script.share(SECRET_PROMPTS, current, new, new)
    return script


def unblock_pin_script(*, admin_pin: SecureBytes, new_user_pin: SecureBytes) -> PromptScript:
    """Reset a blocked user PIN using the admin PIN."""
    _reject_control_characters(admin_pin, what="the admin PIN")
    _reject_control_characters(new_user_pin, what="the new PIN")

    script = PromptScript()
    script.add(PROMPT_CARD_MENU, "admin", "passwd", "quit")
    script.add(PROMPT_PIN_MENU, "2", "Q")
    script.share(SECRET_PROMPTS, admin_pin, new_user_pin, new_user_pin)
    return script


def keytocard_script(
    slot: CardSlot,
    *,
    key_index: int,
    key_passphrase: SecureBytes,
    admin_pin: SecureBytes,
) -> PromptScript:
    """Move one key of the currently edited keyblock onto the card.

    ``key_index`` is GnuPG's subkey number: 0 selects the primary key, 1 the
    first subkey, and so on. The move is irreversible — GnuPG replaces the local
    secret key with a stub pointing at the card.
    """
    _reject_control_characters(admin_pin, what="the admin PIN")

    script = PromptScript()
    if key_index > 0:
        script.add(PROMPT_KEY_MENU, f"key {key_index}", "keytocard", "save")
    else:
        script.add(PROMPT_KEY_MENU, "keytocard", "save")
        # Only asked when the primary key itself is being moved.
        script.add(PROMPT_USE_PRIMARY, YES)
    script.add(PROMPT_SLOT, slot.value)
    script.add(PROMPT_SAVE, YES)
    script.share(SECRET_PROMPTS, key_passphrase, admin_pin)
    return script


def generate_on_card_script(
    *,
    admin_pin: SecureBytes,
    user_pin: SecureBytes,
    name: str,
    email: str,
    expiry: str,
    off_card_backup: bool,
    replace_existing: bool,
) -> PromptScript:
    """Generate a fresh key set on the card itself.

    ``replace_existing`` is answered to GnuPG's "Replace existing keys?" prompt.
    It is passed in rather than defaulted to yes so that overwriting a populated
    card is always a decision the caller made explicitly.
    """
    _reject_control_characters(admin_pin, what="the admin PIN")
    _reject_control_characters(user_pin, what="the PIN")

    script = PromptScript()
    script.add(PROMPT_CARD_MENU, "admin", "generate", "quit")
    script.add(PROMPT_REPLACE_KEYS, YES if replace_existing else NO)
    script.add(PROMPT_BACKUP_ENC, YES if off_card_backup else NO)
    script.add(PROMPT_EXPIRY, expiry)
    script.add(PROMPT_NAME, name)
    script.add(PROMPT_EMAIL, email)
    script.add(PROMPT_COMMENT, "")
    script.add(PROMPT_USERID_CMD, "O")
    script.share(SECRET_PROMPTS, admin_pin, user_pin)
    return script


def card_operation_failed(records: Sequence[Sequence[str]]) -> str | None:
    """Return the failure code from ``SC_OP_FAILURE``, or ``None`` if fine.

    GnuPG exits 0 for several card errors, so the status records — not the
    return code — decide whether an operation actually happened.
    """
    for record in records:
        if record and record[0] == STATUS_FAILURE:
            return record[1] if len(record) > 1 else "unknown"
    return None


def card_operation_succeeded(records: Sequence[Sequence[str]]) -> bool:
    return any(record and record[0] == STATUS_OK for record in records)
