"""Offline crack-time estimator.

This module does **not** attack any system or account. It answers a purely
theoretical, defensive question: *given a password's character composition,
how long would an offline attacker need to exhaust the keyspace?*

The estimate is the classic keyspace / guess-rate calculation:

    combinations = pool_size ** length
    seconds      = (combinations / 2) / guesses_per_second

Dividing by two gives the expected time to find the password (on average an
attacker searches half the space). Several representative attacker profiles are
provided so users can see how hashing choices change the picture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict

from toolkit.strength import _character_pool  # reuse the same pool model

# Representative offline guess rates (guesses per second). These are rough,
# order-of-magnitude figures meant for education, not precise benchmarks.
ATTACKER_PROFILES: Dict[str, float] = {
    "online_throttled": 1e2,        # 100/s  - rate-limited login endpoint
    "online_unthrottled": 1e4,      # 10k/s  - no lockout, single host
    "offline_slow_hash": 1e4,       # 10k/s  - bcrypt/PBKDF2 on a GPU
    "offline_fast_hash": 1e10,      # 10B/s  - unsalted MD5/SHA1 on a GPU rig
}

_SECONDS = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86_400,
    "year": 31_557_600,  # Julian year
}


@dataclass
class CrackEstimate:
    """Result of a crack-time estimation."""

    password_length: int
    pool_size: int
    combinations: float
    # Maps attacker-profile name -> seconds to exhaust half the keyspace.
    seconds_by_profile: Dict[str, float] = field(default_factory=dict)
    human_by_profile: Dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "password_length": self.password_length,
            "pool_size": self.pool_size,
            # combinations can be astronomically large; send it as a string.
            "combinations": f"{self.combinations:.3e}",
            "seconds_by_profile": {
                k: (f"{v:.3e}" if v != float("inf") else "inf")
                for k, v in self.seconds_by_profile.items()
            },
            "human_by_profile": self.human_by_profile,
        }


def humanize_seconds(seconds: float) -> str:
    """Turn a raw second count into a readable span."""
    if seconds == float("inf"):
        return "effectively forever"
    if seconds < 1:
        return "less than a second"
    if seconds < _SECONDS["minute"]:
        return f"{seconds:.0f} seconds"
    if seconds < _SECONDS["hour"]:
        return f"{seconds / _SECONDS['minute']:.1f} minutes"
    if seconds < _SECONDS["day"]:
        return f"{seconds / _SECONDS['hour']:.1f} hours"
    if seconds < _SECONDS["year"]:
        return f"{seconds / _SECONDS['day']:.1f} days"

    years = seconds / _SECONDS["year"]
    if years < 1_000:
        return f"{years:.1f} years"
    if years < 1e6:
        return f"{years / 1e3:.1f} thousand years"
    if years < 1e9:
        return f"{years / 1e6:.1f} million years"
    if years < 1e12:
        return f"{years / 1e9:.1f} billion years"
    return f"{years:.3e} years"


def estimate_crack_time(password: str) -> CrackEstimate:
    """Estimate time to brute-force ``password`` under several attacker models."""
    length = len(password)
    pool = _character_pool(password)

    combinations = float(pool) ** length if pool and length else 0.0
    # Expected guesses to find the password is half the keyspace.
    expected_guesses = combinations / 2 if combinations else 0.0

    seconds_by_profile: Dict[str, float] = {}
    human_by_profile: Dict[str, str] = {}
    for name, rate in ATTACKER_PROFILES.items():
        seconds = expected_guesses / rate if rate else float("inf")
        seconds_by_profile[name] = seconds
        human_by_profile[name] = humanize_seconds(seconds)

    return CrackEstimate(
        password_length=length,
        pool_size=pool,
        combinations=combinations,
        seconds_by_profile=seconds_by_profile,
        human_by_profile=human_by_profile,
    )
