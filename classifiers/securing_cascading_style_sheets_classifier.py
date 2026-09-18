"""Securing Cascading Style Sheets Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Securing Cascading Style Sheets Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Securing_Cascading_Style_Sheets_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python securing_cascading_style_sheets_classifier.py "some text to classify"
    python securing_cascading_style_sheets_classifier.py --file path/to/content.txt
    echo "some text" | python securing_cascading_style_sheets_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Securing Cascading Style Sheets Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Securing_Cascading_Style_Sheets_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "global_stylesheet_information_disclosure": (
        "A single, shared CSS file contains selectors for every application role "
        "(e.g. Student, Teacher, Administrator), letting an unauthenticated "
        "attacker view-source it to learn about restricted features and roles."
    ),
    "descriptive_selector_feature_mapping": (
        "CSS class or ID names are written descriptively (e.g. '.deleteUser', "
        "'.exportUserData', '.addNewAdmin'), directly revealing the existence of "
        "sensitive application features to anyone reading the stylesheet."
    ),
    "missing_role_based_css_isolation": (
        "CSS is not split into per-role files (e.g. StudentStyling.css vs "
        "AdministratorStyling.css) with access control enforcement, so a lower- "
        "privileged user could request a higher-privileged role's stylesheet."
    ),
    "unobfuscated_css_build_output": (
        "CSS selectors are shipped without minification/obfuscation tooling (CSS "
        "Modules, JSS, Blazor CSS isolation, or a base framework like "
        "Bootstrap/Tailwind) that would hide feature-revealing class names."
    ),
    "malicious_user_supplied_css": (
        "User-authored HTML/CSS input is rendered with styling capabilities that "
        "could be abused for UI redress or clickjacking, such as manipulating "
        "layout so a click anywhere loads a malicious page."
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
