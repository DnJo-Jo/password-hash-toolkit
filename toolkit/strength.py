"""Password strength analysis.

Estimates password entropy from its character composition, flags common
weaknesses, and produces a human-readable score. This is a defensive helper:
it tells a user how robust a password is *before* they rely on it.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import List

# A small built-in set of the most common passwords. In a real deployment you
# would load a larger list (e.g. the "rockyou" top-N) from disk.
COMMON_PASSWORDS = {
    "123456", "123456789", "password", "qwerty", "12345678", "111111",
    "1234567", "sunshine", "iloveyou", "princess", "admin", "welcome",
    "666666", "abc123", "football", "123123", "monkey", "654321",
    "letmein", "dragon", "passw0rd", "master", "hello", "login",
    "qwerty123", "000000", "superman", "trustno1",
}

# Character-class sizes used for the entropy pool estimate.
_LOWER = 26
_UPPER = 26
_DIGITS = 10
_SYMBOLS = 33  # printable ASCII punctuation / space


@dataclass
class StrengthResult:
    """Outcome of a strength analysis."""

    password_length: int
    entropy_bits: float
    pool_size: int
    score: int               # 0-4, higher is stronger
    label: str               # "Very weak" .. "Very strong"
    warnings: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "password_length": self.password_length,
            "entropy_bits": round(self.entropy_bits, 2),
            "pool_size": self.pool_size,
            "score": self.score,
            "label": self.label,
            "warnings": self.warnings,
            "suggestions": self.suggestions,
        }


_SCORE_LABELS = {
    0: "Very weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very strong",
}


def _character_pool(password: str) -> int:
    """Return the size of the character pool the password draws from."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += _LOWER
    if re.search(r"[A-Z]", password):
        pool += _UPPER
    if re.search(r"[0-9]", password):
        pool += _DIGITS
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += _SYMBOLS
    return pool


def _has_sequential_run(password: str, run: int = 3) -> bool:
    """Detect runs like 'abc', '123' or repeated characters like 'aaa'."""
    lowered = password.lower()
    for i in range(len(lowered) - run + 1):
        window = lowered[i:i + run]
        codes = [ord(c) for c in window]
        ascending = all(b - a == 1 for a, b in zip(codes, codes[1:]))
        same = all(c == codes[0] for c in codes)
        if ascending or same:
            return True
    return False


def analyze_strength(password: str) -> StrengthResult:
    """Analyze ``password`` and return a :class:`StrengthResult`."""
    length = len(password)
    pool = _character_pool(password)
    entropy = length * math.log2(pool) if pool else 0.0

    warnings: List[str] = []
    suggestions: List[str] = []

    if length == 0:
        return StrengthResult(0, 0.0, 0, 0, _SCORE_LABELS[0],
                              ["Password is empty."],
                              ["Enter a password of at least 12 characters."])

    if password.lower() in COMMON_PASSWORDS:
        warnings.append("This is one of the most commonly used passwords.")
        # Common passwords are trivially guessable regardless of entropy.
        entropy = min(entropy, 10.0)

    if length < 8:
        warnings.append("Shorter than 8 characters.")
        suggestions.append("Use at least 12 characters.")
    elif length < 12:
        suggestions.append("Consider using 12+ characters.")

    if pool <= _LOWER:
        suggestions.append("Mix in uppercase letters, digits and symbols.")
    if not re.search(r"[0-9]", password):
        suggestions.append("Add one or more digits.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        suggestions.append("Add one or more symbols.")

    if _has_sequential_run(password):
        warnings.append("Contains sequential or repeated characters (e.g. 'abc', '111').")
        suggestions.append("Avoid predictable sequences and repeats.")

    # Map entropy to a 0-4 score.
    if entropy < 28:
        score = 0
    elif entropy < 36:
        score = 1
    elif entropy < 60:
        score = 2
    elif entropy < 128:
        score = 3
    else:
        score = 4

    # A known common password can never rank above "weak".
    if password.lower() in COMMON_PASSWORDS:
        score = min(score, 1)

    return StrengthResult(
        password_length=length,
        entropy_bits=entropy,
        pool_size=pool,
        score=score,
        label=_SCORE_LABELS[score],
        warnings=warnings,
        suggestions=suggestions,
    )
