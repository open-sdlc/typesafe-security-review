"""Authorization Testing Automation Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Authorization Testing Automation Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python authorization_testing_automation_classifier.py "some text to classify"
    python authorization_testing_automation_classifier.py --file path/to/content.txt
    echo "some text" | python authorization_testing_automation_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Authorization Testing Automation Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_authorization_matrix": (
        "The application's authorizations (which logical role can access which "
        "feature, optionally filtered by data) are not formalized into a "
        "structured, pivot-format authorization matrix that a program can "
        "process."
    ),
    "untested_release_impact_on_authz": (
        "A new release adds or modifies features without automated tests "
        "verifying whether the change conflicts with the existing authorization "
        "matrix, relying instead only on manual review at creation time."
    ),
    "manual_only_authorization_verification": (
        "Authorization correctness is checked only through manual security audits "
        "at a point in time rather than through integration tests that run "
        "automatically on every build."
    ),
    "undefined_role_hierarchy": (
        "Logical roles (e.g. ANONYMOUS, BASIC, ADMIN) and the access level each "
        "represents are not clearly enumerated or described, making it ambiguous "
        "which combinations of role and service should be allowed."
    ),
    "inconsistent_access_response_codes": (
        "A service returns inconsistent, unexpected, or ambiguous HTTP response "
        "codes for allowed versus denied access attempts, breaking an automated "
        "test's ability to assert correct authorization behavior."
    ),
    "point_of_view_coverage_gap": (
        "Automated authorization tests fail to exercise every relevant role or "
        "'point of view' against every exposed service/endpoint in the "
        "authorization matrix."
    ),
    "data_level_filtering_untested": (
        "Automated authorization tests cover only the feature and role dimensions "
        "but omit the data dimension -- verifying that a role only sees the "
        "business data it is entitled to, not just whether it can call the "
        "endpoint."
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
