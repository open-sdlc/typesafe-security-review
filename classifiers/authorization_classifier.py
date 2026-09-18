"""Authorization Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Authorization Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python authorization_classifier.py "some text to classify"
    python authorization_classifier.py --file path/to/content.txt
    echo "some text" | python authorization_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Authorization Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_least_privilege_enforcement": (
        "A user or role is granted more privileges than the minimum required for "
        "their specific job function, violating the Least Privilege principle "
        "either horizontally (peers with different needs) or vertically (across a "
        "hierarchy)."
    ),
    "fail_open_default_access": (
        "The application permits access by default when no explicit authorization "
        "rule matches a request, instead of adopting a deny-by-default posture."
    ),
    "inconsistent_per_request_authorization": (
        "Authorization is validated on some request paths (e.g. only through the "
        "UI) but not consistently on every request regardless of origin (AJAX, "
        "server-side, direct API call), leaving a gap an attacker only needs to "
        "find once."
    ),
    "overreliance_on_framework_authz_defaults": (
        "An application trusts a third-party library's or framework's default or "
        "unreviewed authorization configuration/logic instead of validating that "
        "it actually meets the app's specific security requirements."
    ),
    "rbac_insufficient_granularity": (
        "A coarse Role-Based Access Control model is used to express access "
        "decisions that actually require fine-grained, multi-factor logic -- "
        "object-level or relationship-based rules that Attribute- or "
        "Relationship-Based Access Control (ABAC/ReBAC) would better support."
    ),
    "horizontal_privilege_elevation": (
        "An authenticated user is able to access or modify another user's "
        "resources despite holding the same privilege level, one of the most "
        "common authorization weaknesses."
    ),
    "unattributed_authorization_violation": (
        "An authorization bypass or violation goes undetected, or cannot be "
        "attributed to a specific individual or group, because access-control "
        "logging was not properly configured."
    ),
    "unreviewed_privilege_creep": (
        "User privileges in the current environment have drifted beyond what was "
        "defined during the design phase because permissions were never "
        "periodically reviewed after being granted."
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
