"""Secure Code Review Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Secure Code Review Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python secure_code_review_classifier.py "some text to classify"
    python secure_code_review_classifier.py --file path/to/content.txt
    echo "some text" | python secure_code_review_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Secure Code Review Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "injection_vulnerability_pattern": (
        "Code under review builds a SQL, NoSQL, or OS command by concatenating "
        "unvalidated input (string concatenation in a query, unsafe query "
        "construction, or direct command execution with user input)."
    ),
    "xss_output_encoding_gap": (
        "User input is rendered into a DOM or HTML response without proper output "
        "encoding, or DOM manipulation exposes unescaped user-controlled content."
    ),
    "path_traversal_file_handling": (
        "A file path is constructed using unvalidated input, enabling directory "
        "traversal to read or write files outside the intended directory."
    ),
    "authn_session_management_weakness": (
        "The reviewed code shows weak authentication mechanisms, insecure session "
        "token generation, or improper handling of user credentials."
    ),
    "broken_access_control": (
        "Authorization checks, role-based access control, or privilege-escalation "
        "prevention are missing or incorrectly implemented for a sensitive "
        "operation."
    ),
    "insecure_deserialization_or_xxe": (
        "Untrusted data is deserialized into objects without validation, or an "
        "XML parser processes external entities without hardening against XXE."
    ),
    "cryptographic_implementation_flaw": (
        "An encryption algorithm, key-management approach, or cryptographic "
        "primitive is implemented or configured incorrectly (e.g. weak algorithm, "
        "hardcoded key, missing IV)."
    ),
    "race_condition_toctou": (
        "Code contains a time-of-check-to-time-of-use gap or non-atomic operation "
        "in concurrent access to a shared resource, enabling a race-condition "
        "exploit."
    ),
    "business_logic_workflow_bypass": (
        "A multi-step workflow's state transitions, quota enforcement, or per- "
        "step authorization can be skipped or manipulated, letting a step be "
        "bypassed."
    ),
    "hardcoded_secret_in_source": (
        "A password, API key, or other secret is embedded directly in source code "
        "or configuration rather than loaded from a secret manager or environment "
        "variable."
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
