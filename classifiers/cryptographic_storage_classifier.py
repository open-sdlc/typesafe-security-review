"""Cryptographic Storage Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Cryptographic Storage Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python cryptographic_storage_classifier.py "some text to classify"
    python cryptographic_storage_classifier.py --file path/to/content.txt
    echo "some text" | python cryptographic_storage_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Cryptographic Storage Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "weak_or_custom_algorithm_usage": (
        "Sensitive data at rest is protected with a weak, outdated, or "
        "custom/home-grown encryption algorithm instead of an accepted "
        "standard like AES-128/256 or ECC/Curve25519 (or RSA >= 2048 bits)."
    ),
    "insecure_cipher_mode": (
        "A block cipher is used in an insecure mode such as ECB, or in a "
        "non-authenticated mode (CBC/CTR) without a separate authentication "
        "step like Encrypt-then-MAC, instead of an authenticated mode such as "
        "GCM or CCM."
    ),
    "missing_random_padding_for_asymmetric_encryption": (
        "RSA encryption is performed without secure random padding (OAEP), "
        "leaving the scheme vulnerable to known plaintext attacks."
    ),
    "insecure_random_number_generation": (
        "A non-cryptographic pseudo-random number generator (PRNG) is used "
        "to produce security-sensitive values such as encryption keys, IVs, "
        "session IDs, or CSRF/password-reset tokens, instead of a "
        "cryptographically secure PRNG (CSPRNG)."
    ),
    "unreliable_uuid_based_randomness": (
        "A UUID/GUID is used as a source of security-critical randomness "
        "without verifying it is a properly-random version (e.g. mistakenly "
        "relying on a version 1, timestamp/MAC-based UUID)."
    ),
    "hardcoded_or_unprotected_keys": (
        "Cryptographic keys are hard-coded in source code, checked into "
        "version control, stored in plaintext configuration files, or placed "
        "in environment variables where they could be accidentally exposed "
        "(e.g. via phpinfo() or /proc/self/environ)."
    ),
    "missing_key_rotation_process": (
        "There is no defined process or cryptoperiod for rotating encryption "
        "keys after suspected compromise, elapsed time, volume of data "
        "encrypted, or a newly discovered algorithm weakness."
    ),
    "missing_separation_of_keys_and_data": (
        "Encryption keys are stored alongside the encrypted data they "
        "protect (same database, same server) rather than in a separate "
        "location/system, or a Key Encryption Key (KEK) is not used to "
        "separately protect a Data Encryption Key (DEK)."
    ),
    "overly_broad_sensitive_data_retention": (
        "Sensitive data (such as credit card numbers) is stored at all when "
        "it did not need to be retained, increasing the impact of any future "
        "key or storage compromise."
    ),
    "insufficient_defense_in_depth_around_encrypted_data": (
        "The application assumes encryption alone is sufficient protection "
        "and does not layer additional access controls around encrypted "
        "fields or URL parameters in case the cryptographic controls fail."
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
