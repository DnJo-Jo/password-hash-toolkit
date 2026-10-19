# Password & Hash Toolkit

An educational, defensive-security toolkit that brings three related password
tasks together behind one simple interface:

1. **Strength analysis** — estimates entropy from character composition and
   flags common weaknesses (too short, common password, sequential runs).
2. **Crack-time estimation** — an *offline, theoretical* estimate of how long
   different attacker profiles would need to brute-force the password. It does
   not attack any system or account.
3. **Hashing** — correct password storage with **PBKDF2-HMAC-SHA256** (random
   salt, 310k iterations) plus plain digests (MD5/SHA-1/SHA-256/SHA-512) for
   checksums and teaching why fast hashes are unsuitable for passwords.

Everything is usable from a **CLI** and from a small **Flask web dashboard**.

> ⚠️ This project is for learning and for testing passwords **you own**. Do not
> use it against accounts, systems, or data you are not authorized to assess.

---

## Project layout

```
.
├── app.py                 # Flask dashboard (routes only; logic lives in toolkit/)
├── cli.py                 # Command-line interface
├── toolkit/
│   ├── __init__.py
│   ├── strength.py        # entropy + weakness analysis
│   ├── hashing.py         # PBKDF2 storage + plain digests
│   └── bruteforce.py      # offline crack-time estimator
├── templates/index.html   # dashboard page
├── static/style.css
├── static/app.js
├── tests/test_toolkit.py  # pytest suite
├── requirements.txt
└── requirements-dev.txt
```

The `toolkit` package has **no third-party dependencies** (standard library
only); Flask is needed only for the web dashboard.

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run the web dashboard

```bash
python app.py
```

Then open <http://127.0.0.1:5000>. Type a password to see a live strength meter
and crack-time table; hash text; and verify a password against a stored hash.
Submitted passwords are processed in-memory and are never stored or logged.

## Use the CLI

```bash
python cli.py analyze "correct horse battery staple"
python cli.py crack   "Tr0ub4dor&3"
python cli.py hash    "my-secret"                 # -> pbkdf2_sha256$...
python cli.py verify  "my-secret" "pbkdf2_sha256$310000$...$..."
python cli.py digest  "hello" --algorithm sha256
```

## Use as a library

```python
from toolkit import analyze_strength, estimate_crack_time, hash_password, verify_password

result = analyze_strength("hunter2")
print(result.score, result.label, result.entropy_bits)

stored = hash_password("hunter2")
assert verify_password("hunter2", stored)
```

---

## Running tests

```bash
pip install -r requirements-dev.txt
pytest
```

---

## How the numbers are calculated

**Entropy** uses the standard pool model: `bits = length × log2(pool_size)`,
where `pool_size` is the sum of the character classes present (lowercase 26,
uppercase 26, digits 10, symbols 33).

**Crack time** uses `combinations = pool_size ^ length`, assumes an attacker
finds the password after searching half the keyspace on average, and divides by
representative guess rates for several attacker profiles (from a rate-limited
login endpoint up to an offline GPU rig against unsalted fast hashes). These are
order-of-magnitude educational figures, not precise benchmarks.

## License

Released under the MIT License — see [LICENSE](LICENSE).
