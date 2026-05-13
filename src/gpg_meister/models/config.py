"""Non-secret application settings.

Loaded from `config.toml`. Passphrases are NEVER stored here. See planv2.md §12.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from gpg_meister.models.kdf_params import KDFProfile
from gpg_meister.models.vault import CipherAlgorithm


class Locale(StrEnum):
    EN = "en"
    DE = "de"
    AUTO = "auto"


class AppearanceMode(StrEnum):
    SYSTEM = "system"
    LIGHT = "light"
    DARK = "dark"


class AuditConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    hash_chain: bool = False


class GPGBinaryTrust(BaseModel):
    """Records a user-approved GPG binary that lies outside the standard whitelist."""

    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    locale: Locale = Locale.AUTO
    appearance: AppearanceMode = AppearanceMode.SYSTEM
    gpg_binary_path: str | None = None
    gpg_binary_trusted_hash: GPGBinaryTrust | None = None
    cipher: CipherAlgorithm = CipherAlgorithm.CHACHA20_POLY1305
    kdf_profile: KDFProfile = KDFProfile.HIGH_MEMORY
    clipboard_clear_seconds: int = Field(default=60, ge=0, le=3600)
    backup_reminder_days: int = Field(default=30, ge=1, le=365)
    high_contrast: bool = False
    reduce_motion: bool = False
    require_delete_text_confirmation: bool = True
    audit: AuditConfig = Field(default_factory=AuditConfig)
