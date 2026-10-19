"""Hashing helpers.

Two distinct concerns live here:

* :func:`digest` computes a plain cryptographic hash of arbitrary text
  (MD5/SHA-1/SHA-256/...). This is useful for file checksums and for
  *demonstrating* why fast hashes are unsuitable for passwords.

* :func:`hash_password` / :func:`verify_password` implement proper password
  storage using PBKDF2-HMAC-SHA256 with a random per-password salt. This is
  what an application should actually use.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import base64

# Fast, general-purpose digest algorithms exposed to the UI/CLI.
ALGORITHMS = ("md5", "sha1", "sha256", "sha512")

# PBKDF2 parameters. The iteration count trades speed for brute-force
# resistance; 310_000 follows current OWASP guidance for PBKDF2-HMAC-SHA256.
_PBKDF2_ALGO = "sha256"
_PBKDF2_ITERATIONS = 310_000
_SALT_BYTES = 16


def digest(text: str, algorithm: str = "sha256") -> str:
    """Return the hex digest of ``text`` using ``algorithm``.

    Raises :class:`ValueError` for an unsupported algorithm.
    """
    algorithm = algorithm.lower()
    if algorithm not in ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm {algorithm!r}. Choose one of {ALGORITHMS}."
        )
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def hash_password(password: str, *, iterations: int = _PBKDF2_ITERATIONS) -> str:
    """Hash a password for storage.

    Returns a self-describing string of the form::

        pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>

    A fresh random salt is generated for every call.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    salt = os.urandom(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        _PBKDF2_ALGO, password.encode("utf-8"), salt, iterations
    )
    return "pbkdf2_{algo}${iters}${salt}${hash}".format(
        algo=_PBKDF2_ALGO,
        iters=iterations,
        salt=base64.b64encode(salt).decode("ascii"),
        hash=base64.b64encode(derived).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    """Verify ``password`` against a value produced by :func:`hash_password`.

    Uses a constant-time comparison to avoid timing side channels. Returns
    ``False`` for a malformed ``stored`` value rather than raising.
    """
    try:
        scheme, iters, salt_b64, hash_b64 = stored.split("$")
        if not scheme.startswith("pbkdf2_"):
            return False
        algo = scheme.split("_", 1)[1]
        iterations = int(iters)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False

    derived = hashlib.pbkdf2_hmac(
        algo, password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(derived, expected)
