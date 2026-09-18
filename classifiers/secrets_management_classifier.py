"""Secrets Management Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Secrets Management Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python secrets_management_classifier.py "some text to classify"
    python secrets_management_classifier.py --file path/to/content.txt
    echo "some text" | python secrets_management_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Secrets Management Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "hardcoded_plaintext_secret": (
        "An API key, database credential, SSH key, certificate, or other secret "
        "is hardcoded in source code, configuration files, or configuration "
        "management tooling in plaintext rather than a secrets manager."
    ),
    "decentralized_secrets_sprawl": (
        "Different teams or applications each use their own ad hoc, non- "
        "standardized secret storage approach, making it unclear what a secret is "
        "used for or where to find it during an incident."
    ),
    "excessive_human_secret_access": (
        "Engineers or broad groups of users are granted standing read/update "
        "access to secrets in the secrets management system, violating least "
        "privilege for who can touch a given secret."
    ),
    "manual_or_static_secret_rotation": (
        "Secrets (especially database credentials or API keys) are long-lived and "
        "rotated manually or not at all, rather than using dynamic, short-lived, "
        "or automatically rotated credentials."
    ),
    "insecure_secret_transmission": (
        "A newly provisioned credential is transmitted insecurely, e.g. sending a "
        "password together with its username in the same message rather than via "
        "a secure or separate side-channel."
    ),
    "secrets_lingering_in_memory": (
        "A secret is held in an immutable/garbage-collected structure (e.g. a "
        "String) after use instead of a zeroable primitive type, and is not "
        "zeroed out of memory once no longer needed."
    ),
    "missing_secret_audit_trail": (
        "There is no record of who requested, approved, used, rotated, or let a "
        "secret expire, making it impossible to reconstruct how a leaked secret "
        "was accessed."
    ),
    "unmanaged_secret_lifecycle": (
        "A secret has no defined creation, rotation, revocation, or expiration "
        "process, so a compromised or obsolete credential could remain valid "
        "indefinitely."
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
