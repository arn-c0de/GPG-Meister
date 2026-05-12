"""Argon2id parameter set used for vault key derivation."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

# RFC 9106 lower bound for the high-memory profile is 19 MiB / 2 iterations / 1 lane.
MIN_TIME_COST = 2
MIN_MEMORY_COST_KB = 19_456
MIN_HASH_LEN = 32
MIN_SALT_LEN = 16

# Hard ceilings. Untrusted vault headers cannot request more than these — preventing
# memory/CPU exhaustion DoS via a forged header (planv2.md threat model).
# 2 GiB memory and 20 iterations are far above any real high-security profile.
MAX_TIME_COST = 20
MAX_MEMORY_COST_KB = 2 * 1024 * 1024  # 2 GiB
MAX_HASH_LEN = 64
MAX_SALT_LEN = 64
MAX_PARALLELISM = 64


class KDFAlgorithm(StrEnum):
    ARGON2ID = "argon2id"


class KDFProfile(StrEnum):
    HIGH_MEMORY = "high_memory"
    BALANCED = "balanced"


class KDFParams(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: KDFAlgorithm = KDFAlgorithm.ARGON2ID
    time_cost: int = Field(..., ge=MIN_TIME_COST, le=MAX_TIME_COST)
    memory_cost: int = Field(..., ge=MIN_MEMORY_COST_KB, le=MAX_MEMORY_COST_KB)
    parallelism: int = Field(..., ge=1, le=MAX_PARALLELISM)
    hash_len: int = Field(..., ge=MIN_HASH_LEN, le=MAX_HASH_LEN)
    salt_len: int = Field(..., ge=MIN_SALT_LEN, le=MAX_SALT_LEN)


def high_memory_params() -> KDFParams:
    """RFC 9106 high-memory profile (256 MiB, 3 iterations, 4 lanes)."""
    return KDFParams(
        algorithm=KDFAlgorithm.ARGON2ID,
        time_cost=3,
        memory_cost=262_144,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )


def balanced_params() -> KDFParams:
    """Lower-memory profile for hosts with limited RAM (64 MiB, 4 iterations)."""
    return KDFParams(
        algorithm=KDFAlgorithm.ARGON2ID,
        time_cost=4,
        memory_cost=65_536,
        parallelism=4,
        hash_len=32,
        salt_len=16,
    )


def params_for_profile(profile: KDFProfile) -> KDFParams:
    if profile is KDFProfile.HIGH_MEMORY:
        return high_memory_params()
    return balanced_params()
