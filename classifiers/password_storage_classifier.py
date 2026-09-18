"""Password Storage Cheat Sheet classifier built on the TypeSafe System One
API.

Classifies input text against sub-categories drawn from the OWASP
"Password Storage Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python password_storage_classifier.py "some text to classify"
    python password_storage_classifier.py --file path/to/content.txt
    echo "some text" | python password_storage_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Password Storage Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Password_Storage_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's hashing, salting, peppering,
# and work-factor guidance. Each description is written so Jev (the
# TypeSafe model) can distinguish it from neighboring categories -- be
# specific about what does and does not count.
CATEGORIES = {
    "plaintext_or_reversible_storage": (
        "Passwords are stored in plaintext or protected only with reversible "
        "(two-way) encryption instead of a one-way adaptive hashing "
        "algorithm."
    ),
    "fast_hash_algorithm_misuse": (
        "A fast, general-purpose hash function such as MD5, SHA-1, or plain "
        "SHA-256 is used to hash passwords instead of a slow, memory-hard "
        "algorithm like Argon2id, bcrypt, scrypt, or PBKDF2."
    ),
    "missing_or_reused_salt": (
        "Passwords are hashed without a unique, per-password random salt, "
        "enabling precomputed rainbow-table attacks or revealing when two "
        "users share the same password."
    ),
    "weak_work_factor_configuration": (
        "The password hashing algorithm's cost parameters (Argon2id memory/"
        "iterations/parallelism, scrypt N/r/p, bcrypt work factor, or PBKDF2 "
        "iteration count) are configured below recommended minimums, making "
        "hashes cheaper to brute-force."
    ),
    "bcrypt_length_or_prehash_mishandling": (
        "bcrypt is used without enforcing its ~72-byte input limit, or "
        "passwords are pre-hashed with a fast function before bcrypt in an "
        "unsafe way (e.g. raw binary output causing null-byte truncation), "
        "risking password shucking."
    ),
    "missing_pepper_defense_in_depth": (
        "No secret pepper, stored separately from the password database "
        "(e.g. in an HSM or secrets vault), is applied as additional "
        "defense in case the password database itself is stolen."
    ),
    "static_work_factor_never_upgraded": (
        "The password hashing work factor is never revisited or increased "
        "over time as hardware improves, leaving old hashes progressively "
        "weaker without a re-hash-on-login upgrade path."
    ),
}


def classify_with_nouls(text: str) -> dict:
    """Return dict of category -> probability (0-1), one Noul per category,
    all evaluated in a single parallel call."""
    with TypeSafeClient() as client:
        result = client.system_one(
            state=text,
            questions={
                name: Noul(instructions=f"Does the input relate to or exhibit this issue: {desc}")
                for name, desc in CATEGORIES.items()
            },
        )
    return {name: answer.noul for name, answer in result.nouls.items()}


def print_table(headers, rows) -> None:
    """Print `rows` (each a tuple of column values) as a simple aligned table."""
    widths = [
        max(len(str(cell)) for cell in (header, *(row[i] for row in rows)))
        for i, header in enumerate(headers)
    ]
    def fmt(row):
        return "  ".join(str(cell).ljust(width) for cell, width in zip(row, widths))

    print(fmt(headers))
    print("  ".join("-" * width for width in widths))
    for row in rows:
        print(fmt(row))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("text", nargs="?", help="Text to classify")
    parser.add_argument("--file", help="Read text to classify from a file")
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as fh:
            text = fh.read()
    elif args.text:
        text = args.text
    else:
        text = sys.stdin.read()

    if not text.strip():
        parser.error("no input text provided")

    scores = classify_with_nouls(text)
    rows = [
        (name, f"{prob:.3f}")
        for name, prob in sorted(scores.items(), key=lambda kv: -kv[1])
    ]
    print_table(("category", "probability"), rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
