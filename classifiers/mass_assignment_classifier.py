"""Mass Assignment Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Mass Assignment Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python mass_assignment_classifier.py "some text to classify"
    python mass_assignment_classifier.py --file path/to/content.txt
    echo "some text" | python mass_assignment_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Mass Assignment Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Mass_Assignment_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "unintended_field_binding": (
        "A framework's auto-binding feature (also called autobinding or "
        "object injection depending on the language) maps all incoming "
        "request parameters directly onto a model/object's fields, "
        "including fields the developer never intended to be user-set."
    ),
    "sensitive_field_privilege_escalation": (
        "An attacker adds an unexpected parameter to a request (e.g. "
        "isAdmin=true or a role field) in order to modify a sensitive field "
        "via mass assignment and escalate their own privileges."
    ),
    "missing_allowlist_of_bindable_fields": (
        "The application does not explicitly allow-list which fields are "
        "bindable from user input, such as via Spring's setAllowedFields, "
        "Laravel's $fillable, or an equivalent framework mechanism."
    ),
    "missing_blocklist_of_sensitive_fields": (
        "The application fails to explicitly block-list sensitive fields "
        "from being bound from user input, such as via Spring's "
        "setDisallowedFields, Laravel's $guarded, or a 'protect' flag on a "
        "schema field."
    ),
    "unguarded_model_or_forcefill_bypass": (
        "A model's built-in mass-assignment protection is disabled (e.g. an "
        "unguarded/empty $guarded array) or bypassed via a force-fill/"
        "force-create style method applied to unvalidated request data."
    ),
    "missing_dto_pattern": (
        "Request input is bound directly onto a domain/persistence model "
        "instead of using a Data Transfer Object (DTO) that exposes only "
        "the fields a user is meant to edit."
    ),
    "attacker_source_code_field_discovery": (
        "An attacker with access to the application's source code reviews "
        "its models/schemas to discover sensitive field names (e.g. "
        "isAdmin) to target via mass assignment."
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
