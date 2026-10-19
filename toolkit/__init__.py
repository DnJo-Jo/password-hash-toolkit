"""Password / Hash toolkit.

An educational, defensive-security toolkit that combines:

* :mod:`toolkit.strength`    - password strength & entropy analysis
* :mod:`toolkit.hashing`     - secure and legacy hashing helpers
* :mod:`toolkit.bruteforce`  - an offline crack-time *estimator* (no live attacks)

The package is intentionally dependency-free (standard library only) so it can be
used from the CLI, the Flask dashboard, or imported into other projects.
"""

from toolkit.strength import analyze_strength, StrengthResult
from toolkit.hashing import hash_password, verify_password, digest, ALGORITHMS
from toolkit.bruteforce import estimate_crack_time, CrackEstimate

__all__ = [
    "analyze_strength",
    "StrengthResult",
    "hash_password",
    "verify_password",
    "digest",
    "ALGORITHMS",
    "estimate_crack_time",
    "CrackEstimate",
]

__version__ = "1.0.0"
