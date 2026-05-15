from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QLabel

from gpg_meister.models.key_info import KeyAlgorithm, KeyInfo, TrustLevel
from gpg_meister.models.vault import VaultKeyEntry
from gpg_meister.services.vault_service import VaultPreview
from gpg_meister.ui.keys.first_launch_wizard import _ConfirmPage
from gpg_meister.ui.keys.key_detail_view import KeyDetailView
from gpg_meister.ui.messages.encrypt_view import _RecipientCard
from gpg_meister.ui.vault.vault_import_view import _SelectPage
from gpg_meister.ui.widgets.warning_banner import WarningBanner


def _key_info(uid: str) -> KeyInfo:
    return KeyInfo(
        fingerprint="A" * 40,
        user_ids=(uid,),
        algorithm=KeyAlgorithm.EDDSA,
        length=255,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        trust=TrustLevel.UNKNOWN,
    )


def _vault_preview(description: str) -> VaultPreview:
    return VaultPreview(
        path=Path("/tmp/example.gpgm"),
        created_at=datetime(2026, 1, 2, 3, 4, tzinfo=UTC),
        app_version="1.0.3",
        description=description,
        keys=(
            VaultKeyEntry(
                fingerprint="B" * 40,
                user_ids=("Alice",),
                public_key_armored="pub",
                has_private_key=False,
                created_at=datetime(2026, 1, 1, tzinfo=UTC),
            ),
        ),
    )


class _FakeKeyService:
    def export_public(self, fingerprint: str) -> str:
        return fingerprint


def test_untrusted_labels_use_plain_text() -> None:
    app = QApplication.instance() or QApplication([])
    malicious = "<a href='https://example.invalid'>click</a>"

    banner = WarningBanner(malicious)
    assert banner._message_label.textFormat() is Qt.TextFormat.PlainText

    detail = KeyDetailView(_key_info(malicious), _FakeKeyService())
    uid_labels = [label for label in detail.findChildren(QLabel) if label.text() == malicious]
    assert uid_labels
    assert all(label.textFormat() is Qt.TextFormat.PlainText for label in uid_labels)

    card = _RecipientCard(_key_info(malicious))
    card_labels = [label for label in card.findChildren(QLabel) if label.text() == malicious]
    assert card_labels
    assert all(label.textFormat() is Qt.TextFormat.PlainText for label in card_labels)

    confirm = _ConfirmPage()
    confirm.set_selected([_key_info(malicious)])
    detail_labels = [label for label in confirm.findChildren(QLabel) if malicious in label.text()]
    assert detail_labels
    assert all(label.textFormat() is Qt.TextFormat.PlainText for label in detail_labels)

    preview_page = _SelectPage()
    preview_page._keys = _vault_preview(malicious).keys
    preview_page._meta_label.setText(
        "Vault created: 2026-01-02 03:04 UTC  |  App version: 1.0.3  |  "
        f"Description: {malicious}"
    )
    app.processEvents()
    assert preview_page._meta_label.textFormat() is Qt.TextFormat.PlainText
