"""Authorization Regression Testing Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Authorization Regression Testing Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python authorization_regression_testing_classifier.py "some text to classify"
    python authorization_regression_testing_classifier.py --file path/to/content.txt
    echo "some text" | python authorization_regression_testing_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Authorization Regression Testing Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "idor_regression_gap": (
        "A code, API, or data-layer change reintroduces an Insecure Direct Object "
        "Reference, letting one user read, update, or delete another user's "
        "resource by ID, without an automated 'multi-user replay' regression test "
        "catching the reintroduced flaw."
    ),
    "vertical_escalation_regression_gap": (
        "A refactor lets a lower-privileged or unauthenticated role reach an "
        "administrative endpoint again, because enforcement relies on UI hiding "
        "rather than a server-side check covered by an automated 'role demotion' "
        "regression test."
    ),
    "tenant_isolation_regression": (
        "A caching, query, or data-layer change causes cross-tenant data leakage "
        "in a multi-tenant application, undetected because no automated "
        "cross-tenant boundary test exists."
    ),
    "unstructured_authorization_matrix": (
        "Authorization rules (actor-resource-action mappings) are not maintained "
        "in a machine-readable matrix format (JSON/YAML) that automated test "
        "frameworks can consume, relying instead on scattered, one-off test cases "
        "or a spreadsheet."
    ),
    "openapi_contract_authz_drift": (
        "The authorization requirements declared in an OpenAPI/API contract "
        "(security schemes, required scopes) diverge from what is actually "
        "enforced at runtime, and no test verifies requests lacking the required "
        "scope are rejected."
    ),
    "missing_cicd_authorization_gate": (
        "Authorization regression tests are not configured as a required, "
        "blocking check in the CI/CD pipeline, allowing a pull request that "
        "breaks access control to be merged."
    ),
    "undetected_authz_response_anomaly": (
        "No monitoring exists for unusual volumes of 401/403 responses in CI or "
        "lower environments, which could otherwise reveal that a functional "
        "change collided with existing authorization enforcement."
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
