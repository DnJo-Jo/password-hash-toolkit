"""Unit tests for the toolkit package."""

import math

import pytest

from toolkit import (
    analyze_strength,
    estimate_crack_time,
    hash_password,
    verify_password,
    digest,
)
from toolkit.bruteforce import humanize_seconds


# --- strength --------------------------------------------------------------

def test_empty_password_is_very_weak():
    r = analyze_strength("")
    assert r.score == 0
    assert r.entropy_bits == 0
    assert r.warnings


def test_common_password_capped_low():
    r = analyze_strength("password")
    assert r.score <= 1
    assert any("common" in w.lower() for w in r.warnings)


def test_strong_password_scores_high():
    r = analyze_strength("G7!qLm2@xZ9#pR4$wN")
    assert r.score >= 3
    assert r.pool_size == 26 + 26 + 10 + 33


def test_entropy_matches_formula():
    pw = "abcdWXYZ"  # lower + upper -> pool 52
    r = analyze_strength(pw)
    assert r.pool_size == 52
    assert r.entropy_bits == pytest.approx(len(pw) * math.log2(52))


def test_sequential_run_flagged():
    r = analyze_strength("abcAAA123zzz")
    assert any("sequential" in w.lower() for w in r.warnings)


# --- crack-time ------------------------------------------------------------

def test_crack_estimate_profiles_present():
    est = estimate_crack_time("Abc123!x")
    assert set(est.human_by_profile) == {
        "online_throttled",
        "online_unthrottled",
        "offline_slow_hash",
        "offline_fast_hash",
    }


def test_longer_password_takes_longer():
    short = estimate_crack_time("Ab1!")
    long = estimate_crack_time("Ab1!Ab1!Ab1!")
    assert long.combinations > short.combinations


def test_humanize_seconds():
    assert humanize_seconds(0.5) == "less than a second"
    assert "minutes" in humanize_seconds(120)
    assert humanize_seconds(float("inf")) == "effectively forever"


# --- hashing ---------------------------------------------------------------

def test_digest_known_value():
    # SHA-256 of "abc" is a well-known constant.
    assert digest("abc", "sha256") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_digest_rejects_unknown_algorithm():
    with pytest.raises(ValueError):
        digest("x", "sha3_999")


def test_password_roundtrip():
    stored = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", stored)
    assert not verify_password("wrong password", stored)


def test_hash_uses_random_salt():
    a = hash_password("same")
    b = hash_password("same")
    assert a != b  # different salts -> different stored strings
    assert verify_password("same", a)
    assert verify_password("same", b)


def test_verify_handles_malformed_input():
    assert verify_password("x", "not-a-valid-hash") is False
    assert verify_password("x", "") is False
