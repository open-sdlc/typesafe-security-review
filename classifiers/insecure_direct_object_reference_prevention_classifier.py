"""Insecure Direct Object Reference Prevention Cheat Sheet classifier built on
the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Insecure Direct Object Reference Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python insecure_direct_object_reference_prevention_classifier.py "some text to classify"
    python insecure_direct_object_reference_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python insecure_direct_object_reference_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Insecure Direct Object Reference Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "url_path_object_reference": (
        "An object identifier such as a numeric database ID is exposed "
        "directly in a URL path or query parameter (e.g. /users/123) and "
        "used to fetch that specific record."
    ),
    "hidden_form_field_reference": (
        "An object identifier is passed through a hidden HTML form field or "
        "POST request body (e.g. a hidden 'user_id' input) rather than being "
        "derived from the authenticated user's own session."
    ),
    "non_numeric_reference": (
        "The object reference is a filename, document slug, account number, "
        "or other non-numeric token (not a sequential primary key), but the "
        "application still directly dereferences it without an authorization "
        "check."
    ),
    "missing_object_level_authorization": (
        "The application looks up or modifies an object by its reference "
        "without verifying that the currently authenticated user is actually "
        "permitted to access or change that specific object."
    ),
    "complex_identifier_as_sole_defense": (
        "The content relies on a hard-to-guess complex identifier (a GUID, "
        "UUID, or random string) as the only protection for an object, "
        "instead of pairing it with an explicit access-control check."
    ),
    "cross_account_access_attempt": (
        "A scenario in which one authenticated user (e.g. User A) attempts "
        "to read, modify, or delete an object owned by a different user "
        "(User B) by tampering with the object reference in a request."
    ),
    "multi_step_flow_identifier_tampering": (
        "An object identifier is carried across a multi-step flow (e.g. in a "
        "hidden field or client-side state between steps) where it could be "
        "tampered with before a final action is performed, instead of being "
        "kept in server-side session state."
    ),
    "identifier_encryption_antipattern": (
        "Object identifiers are encrypted as a substitute for proper access "
        "control, an approach the cheat sheet specifically warns is "
        "challenging to do securely and discourages."
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
