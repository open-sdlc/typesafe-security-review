"""Abuse Case Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Abuse Case Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python abuse_case_classifier.py "some text to classify"
    python abuse_case_classifier.py --file path/to/content.txt
    echo "some text" | python abuse_case_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Abuse Case Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "unidentified_business_logic_abuse": (
        "A way to use a feature that its implementer did not anticipate, letting "
        "an attacker influence the feature or its outcome through their own "
        "actions or input -- e.g. locking in a favorable price and holding a "
        "transaction open to exploit later market movement."
    ),
    "account_enumeration_via_flow": (
        "A legitimate feature such as a password-reset flow is abused to "
        "enumerate whether a given account exists, based on differing responses "
        "or behavior."
    ),
    "price_or_value_manipulation": (
        "A user is able to arbitrarily alter a price, value, or other transaction "
        "term of an online-shop or business feature before an order or "
        "transaction is finalized, paying less than intended."
    ),
    "generic_unactionable_security_requirement": (
        "Security requirements are expressed only as vague, generic statements "
        "(e.g. 'the application must be secure' or 'must defend against all OWASP "
        "Top 10 attacks') instead of concrete, feature-specific abuse cases a "
        "development team can act on."
    ),
    "unrated_or_untracked_abuse_case": (
        "An identified abuse case lacks a formal risk rating (e.g. a CVSS score) "
        "or a unique trackable identifier linking it to its feature and any "
        "assigned countermeasure."
    ),
    "missing_countermeasure_mapping": (
        "An abuse case has no corresponding countermeasure defined, or no clear "
        "decision on where the countermeasure should live (network, "
        "infrastructure, or code)."
    ),
    "technical_injection_abuse_case": (
        "An abuse case of a clearly technical nature, such as injecting a "
        "Cross-Site Scripting payload into a comment or input field of a specific "
        "feature."
    ),
    "missing_cross_functional_threat_review": (
        "A feature's attack surface is defined without involving the range of "
        "perspectives needed (business analyst, risk analyst, penetration tester, "
        "technical lead, QA) to surface realistic abuse scenarios before "
        "implementation."
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
