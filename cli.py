#!/usr/bin/env python3
"""Command-line interface for the Password / Hash toolkit.

Examples
--------
    python cli.py analyze "correct horse battery staple"
    python cli.py crack "Tr0ub4dor&3"
    python cli.py hash "my-secret"          # PBKDF2 storage hash
    python cli.py verify "my-secret" "pbkdf2_sha256$310000$...$..."
    python cli.py digest "hello" --algorithm sha256
"""

from __future__ import annotations

import argparse
import sys

from toolkit import (
    analyze_strength,
    estimate_crack_time,
    hash_password,
    verify_password,
    digest,
    ALGORITHMS,
)


def _cmd_analyze(args: argparse.Namespace) -> int:
    result = analyze_strength(args.password)
    print(f"Length       : {result.password_length}")
    print(f"Pool size    : {result.pool_size}")
    print(f"Entropy      : {result.entropy_bits:.2f} bits")
    print(f"Score        : {result.score}/4  ({result.label})")
    if result.warnings:
        print("Warnings:")
        for w in result.warnings:
            print(f"  ! {w}")
    if result.suggestions:
        print("Suggestions:")
        for s in result.suggestions:
            print(f"  - {s}")
    return 0


def _cmd_crack(args: argparse.Namespace) -> int:
    est = estimate_crack_time(args.password)
    print(f"Length       : {est.password_length}")
    print(f"Pool size    : {est.pool_size}")
    print(f"Combinations : {est.combinations:.3e}")
    print("Estimated time to crack (average):")
    for profile, human in est.human_by_profile.items():
        print(f"  {profile:<20} {human}")
    return 0


def _cmd_hash(args: argparse.Namespace) -> int:
    print(hash_password(args.password))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    ok = verify_password(args.password, args.stored)
    print("MATCH" if ok else "NO MATCH")
    return 0 if ok else 1


def _cmd_digest(args: argparse.Namespace) -> int:
    print(digest(args.text, args.algorithm))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password-hash-toolkit",
        description="Educational password strength, hashing and crack-time toolkit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_analyze = sub.add_parser("analyze", help="Analyze password strength.")
    p_analyze.add_argument("password")
    p_analyze.set_defaults(func=_cmd_analyze)

    p_crack = sub.add_parser("crack", help="Estimate brute-force crack time.")
    p_crack.add_argument("password")
    p_crack.set_defaults(func=_cmd_crack)

    p_hash = sub.add_parser("hash", help="Produce a PBKDF2 storage hash.")
    p_hash.add_argument("password")
    p_hash.set_defaults(func=_cmd_hash)

    p_verify = sub.add_parser("verify", help="Verify a password against a stored hash.")
    p_verify.add_argument("password")
    p_verify.add_argument("stored")
    p_verify.set_defaults(func=_cmd_verify)

    p_digest = sub.add_parser("digest", help="Compute a plain cryptographic digest.")
    p_digest.add_argument("text")
    p_digest.add_argument(
        "--algorithm", "-a", default="sha256", choices=ALGORITHMS,
        help="Digest algorithm (default: sha256).",
    )
    p_digest.set_defaults(func=_cmd_digest)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
