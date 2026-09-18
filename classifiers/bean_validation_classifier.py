"""Bean Validation Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Bean Validation Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Bean_Validation_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python bean_validation_classifier.py "some text to classify"
    python bean_validation_classifier.py --file path/to/content.txt
    echo "some text" | python bean_validation_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Bean Validation Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Bean_Validation_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_field_constraint_annotations": (
        "A domain model field that should carry input-validation constraints "
        "(@Pattern, @Size, @Digits, @Min/@Max, @Email, @URL, @CreditCardNumber, "
        "etc.) lacks them, letting malformed or malicious input reach the "
        "application."
    ),
    "unvalidated_cross_layer_input": (
        "Input validation is duplicated or applied inconsistently across "
        "different application tiers instead of being defined once on the domain "
        "model and enforced everywhere via @Valid cascading."
    ),
    "deprecated_unsafe_constraint_usage": (
        "A deprecated or unsafe bean-validation constraint, such as @SafeHtml, is "
        "still used even though it no longer provides a reliable security "
        "guarantee."
    ),
    "missing_cascading_validation": (
        "A nested object graph (a bean referencing other beans) is not validated "
        "with cascading @Valid annotations, letting invalid nested data pass "
        "validation undetected."
    ),
    "unhandled_validation_errors": (
        "Validation failures (a populated BindingResult / list of ObjectError) "
        "are not properly surfaced or handled, risking inconsistent error "
        "responses, silent failures, or information leakage in error messages."
    ),
    "weak_pattern_constraint": (
        "A regex-based @Pattern constraint is too permissive or incorrectly "
        "written, failing to reject malicious or malformed input formats it was "
        "meant to block."
    ),
    "missing_numeric_range_constraints": (
        "A numeric field (quantity, age, rating, monetary amount) lacks "
        "@Min/@Max/@Digits range constraints, allowing out-of-range, negative, or "
        "overflow values to be accepted."
    ),
    "missing_custom_business_constraint": (
        "Only built-in bean-validation constraints are relied upon when a custom, "
        "business-rule-specific constraint would be required to fully validate a "
        "domain-specific input."
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
