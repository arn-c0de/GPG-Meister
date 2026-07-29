"""The loop that answers GnuPG's interactive prompts.

Exercised directly over a pair of pipes: the status side plays GnuPG, the
command side collects what the responder would have typed. No GnuPG, no card.
"""

from __future__ import annotations

import os
import threading

from gpg_meister.services.card_scripts import PromptScript
from gpg_meister.services.gpg_service import _answer_prompts, _prompt_keyword


def _run(script: PromptScript, status_lines: list[bytes]) -> tuple[list[str], dict[str, str]]:
    """Feed ``status_lines`` to the responder; return (answers, outcome)."""
    status_r, status_w = os.pipe()
    command_r, command_w = os.pipe()
    transcript = bytearray()
    outcome: dict[str, str] = {}

    thread = threading.Thread(
        target=_answer_prompts,
        args=(status_r, command_w, script, transcript, outcome),
        daemon=True,
    )
    thread.start()
    try:
        for line in status_lines:
            os.write(status_w, line + b"\n")
        os.close(status_w)
        thread.join(timeout=5.0)
        answers: list[bytes] = []
        while chunk := os.read(command_r, 4096):
            answers.append(chunk)
    finally:
        os.close(command_r)
    return b"".join(answers).decode().splitlines(), outcome


def test_keyword_is_parsed_from_each_prompt_kind() -> None:
    assert _prompt_keyword(b"[GNUPG:] GET_LINE cardedit.prompt") == "cardedit.prompt"
    assert _prompt_keyword(b"[GNUPG:] GET_BOOL cardedit.genkeys.replace_keys") == (
        "cardedit.genkeys.replace_keys"
    )
    assert _prompt_keyword(b"[GNUPG:] GET_HIDDEN passphrase.enter") == "passphrase.enter"


def test_non_prompt_status_lines_are_ignored() -> None:
    assert _prompt_keyword(b"[GNUPG:] CARDCTRL 3 D276000124") is None
    assert _prompt_keyword(b"gpg: OpenPGP card detected") is None
    assert _prompt_keyword(b"[GNUPG:] GET_LINE") is None


def test_each_prompt_is_answered_from_its_own_queue() -> None:
    script = PromptScript()
    script.add("cardedit.prompt", "admin", "passwd", "quit")
    script.add("cardedit.change_pin.menu", "1", "Q")

    answers, outcome = _run(
        script,
        [
            b"[GNUPG:] GET_LINE cardedit.prompt",
            b"[GNUPG:] GET_LINE cardedit.prompt",
            b"[GNUPG:] GET_LINE cardedit.change_pin.menu",
            b"[GNUPG:] GET_LINE cardedit.change_pin.menu",
            b"[GNUPG:] GET_LINE cardedit.prompt",
        ],
    )

    assert answers == ["admin", "passwd", "1", "Q", "quit"]
    assert outcome == {}


def test_prompts_split_across_reads_are_still_answered() -> None:
    """Pipe reads do not respect line boundaries."""
    script = PromptScript()
    script.add("cardedit.prompt", "admin")
    status_r, status_w = os.pipe()
    command_r, command_w = os.pipe()
    outcome: dict[str, str] = {}
    thread = threading.Thread(
        target=_answer_prompts,
        args=(status_r, command_w, script, bytearray(), outcome),
        daemon=True,
    )
    thread.start()
    try:
        os.write(status_w, b"[GNUPG:] GET_LI")
        os.write(status_w, b"NE cardedit.prompt\n")
        os.close(status_w)
        thread.join(timeout=5.0)
        answer = os.read(command_r, 4096)
    finally:
        os.close(command_r)

    assert answer == b"admin\n"


def test_an_unscripted_prompt_stops_the_conversation() -> None:
    """The dangerous case: GnuPG asks something we never planned an answer for.

    Answering anything could confirm a destructive action, so the responder
    closes the command pipe instead — GnuPG then aborts on EOF.
    """
    script = PromptScript()
    script.add("cardedit.prompt", "admin")

    answers, outcome = _run(
        script,
        [
            b"[GNUPG:] GET_LINE cardedit.prompt",
            b"[GNUPG:] GET_BOOL cardedit.genkeys.replace_keys",
            b"[GNUPG:] GET_LINE cardedit.prompt",
        ],
    )

    assert answers == ["admin"]
    assert outcome["unanswered"] == "cardedit.genkeys.replace_keys"


def test_an_exhausted_queue_counts_as_unscripted() -> None:
    script = PromptScript()
    script.add("cardedit.prompt", "admin")

    answers, outcome = _run(
        script,
        [b"[GNUPG:] GET_LINE cardedit.prompt", b"[GNUPG:] GET_LINE cardedit.prompt"],
    )

    assert answers == ["admin"]
    assert outcome["unanswered"] == "cardedit.prompt"


def test_the_status_stream_is_captured_for_diagnosis() -> None:
    script = PromptScript()
    script.add("cardedit.prompt", "quit")
    status_r, status_w = os.pipe()
    command_r, command_w = os.pipe()
    transcript = bytearray()
    thread = threading.Thread(
        target=_answer_prompts,
        args=(status_r, command_w, script, transcript, {}),
        daemon=True,
    )
    thread.start()
    try:
        os.write(status_w, b"[GNUPG:] SC_OP_SUCCESS\n[GNUPG:] GET_LINE cardedit.prompt\n")
        os.close(status_w)
        thread.join(timeout=5.0)
        os.read(command_r, 4096)
    finally:
        os.close(command_r)

    assert b"SC_OP_SUCCESS" in bytes(transcript)
