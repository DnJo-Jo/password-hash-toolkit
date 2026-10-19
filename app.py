#!/usr/bin/env python3
"""Flask dashboard for the Password / Hash toolkit.

Run locally with::

    pip install -r requirements.txt
    python app.py

then open http://127.0.0.1:5000 in a browser.

The dashboard is a client of the :mod:`toolkit` package: all logic lives in
the package, and this file only wires it to HTTP routes. Passwords submitted
here are processed in-memory and never stored or logged.
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from toolkit import (
    analyze_strength,
    estimate_crack_time,
    hash_password,
    verify_password,
    digest,
    ALGORITHMS,
)

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", algorithms=ALGORITHMS)


@app.post("/api/analyze")
def api_analyze():
    """Return strength analysis + crack-time estimate for a password."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not isinstance(password, str):
        return jsonify({"error": "password must be a string"}), 400

    strength = analyze_strength(password)
    crack = estimate_crack_time(password)
    return jsonify({"strength": strength.as_dict(), "crack": crack.as_dict()})


@app.post("/api/hash")
def api_hash():
    """Produce a PBKDF2 storage hash or a plain digest."""
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    mode = data.get("mode", "pbkdf2")
    if not isinstance(text, str):
        return jsonify({"error": "text must be a string"}), 400

    if mode == "pbkdf2":
        return jsonify({"mode": mode, "result": hash_password(text)})

    if mode == "digest":
        algorithm = data.get("algorithm", "sha256")
        try:
            result = digest(text, algorithm)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"mode": mode, "algorithm": algorithm, "result": result})

    return jsonify({"error": f"unknown mode {mode!r}"}), 400


@app.post("/api/verify")
def api_verify():
    """Verify a password against a stored PBKDF2 hash."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    stored = data.get("stored", "")
    if not isinstance(password, str) or not isinstance(stored, str):
        return jsonify({"error": "password and stored must be strings"}), 400
    return jsonify({"match": verify_password(password, stored)})


if __name__ == "__main__":
    # debug=True is convenient for local development only.
    app.run(host="127.0.0.1", port=5000, debug=True)
