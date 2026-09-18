"""Key Management Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Key Management Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python key_management_classifier.py "some text to classify"
    python key_management_classifier.py --file path/to/content.txt
    echo "some text" | python key_management_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Key Management Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Key_Management_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "key_selection_without_requirements": (
        "Cryptographic algorithms or key types are chosen before analyzing "
        "the application's actual security objectives (confidentiality, "
        "authenticity, integrity) that should drive the selection."
    ),
    "weak_key_strength": (
        "A cryptographic key's length or algorithm strength does not meet "
        "current guidance (e.g. NIST SP 800-57) for the required protection "
        "period, or a key is encrypted with a wrapping key of lesser "
        "strength than itself."
    ),
    "key_reuse_across_purposes": (
        "The same cryptographic key is used for more than one purpose (e.g. "
        "both encryption and digital signatures, or both key-wrapping and "
        "authentication) instead of restricting each key to a single "
        "dedicated purpose."
    ),
    "insecure_key_storage": (
        "Cryptographic keys are stored in plaintext, outside a cryptographic "
        "vault/HSM, or without integrity protection while at rest, instead "
        "of being generated, held, and used only inside a protected module."
    ),
    "missing_key_rotation_or_destruction": (
        "The content lacks or violates a defined key lifecycle process for "
        "periodic key rotation, or for destroying/zeroizing keys once they "
        "are no longer needed."
    ),
    "key_backup_and_escrow_gaps": (
        "Key backup or escrow procedures are missing or improperly "
        "protected (e.g. an unencrypted backup database, or escrowing a "
        "digital-signature key), risking permanent data loss or improper "
        "recovery capability."
    ),
    "compromise_recovery_planning": (
        "Content relates to detecting, containing, or recovering from a "
        "suspected or confirmed key compromise, including whether a "
        "documented compromise-recovery plan exists."
    ),
    "trust_store_integrity": (
        "Content relates to protecting a trust store against unauthorized "
        "injection of third-party root certificates or unauthorized export "
        "of key material held within it."
    ),
    "perfect_forward_secrecy": (
        "Content relates to using ephemeral/session keys so that compromise "
        "of a long-term signing or master key does not expose the "
        "confidentiality of past sessions."
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
