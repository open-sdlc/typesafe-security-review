"""Attack Surface Analysis Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Attack Surface Analysis Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python attack_surface_analysis_classifier.py "some text to classify"
    python attack_surface_analysis_classifier.py --file path/to/content.txt
    echo "some text" | python attack_surface_analysis_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Attack Surface Analysis Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "entry_exit_point_mapping_gap": (
        "The full set of paths through which data or commands can enter or leave "
        "the application -- UI forms, HTTP headers/cookies, APIs, files, "
        "databases, messages, runtime arguments -- has not been identified or "
        "inventoried."
    ),
    "unmanaged_attack_surface_growth": (
        "The application's attack surface has grown unnecessarily due to unused "
        "features left enabled, multiple deployed versions running "
        "simultaneously, or old backup copies and dead code left reachable."
    ),
    "privileged_or_anonymous_user_analysis_gap": (
        "Analysis fails to focus on the two extremes of the access model -- fully "
        "unauthenticated anonymous users and highly privileged admin users -- "
        "whose risk profiles differ most."
    ),
    "unassessed_new_technology_change": (
        "A new technology, framework, protocol, or architectural approach (e.g. a "
        "new API type or trust boundary) is introduced without a corresponding "
        "threat assessment of the attack surface it opens."
    ),
    "microservice_cloud_surface_gap": (
        "Microservice or cloud-native components reachable from external/internet "
        "traffic through proxies, load balancers, ingress controllers, or "
        "auto-scaling groups are not prioritized or visualized in the attack "
        "surface analysis."
    ),
    "legacy_backward_compatible_interface": (
        "A backward-compatible or legacy interface/protocol using old code or "
        "libraries is kept active, adding attack surface that is hard to maintain "
        "and test across multiple versions."
    ),
    "unprotected_backup_exposure": (
        "Backups of code or data, whether online or on offline media, are "
        "inadequately protected as part of the application's overall attack "
        "surface."
    ),
    "missing_change_triggered_reassessment": (
        "A change to authentication, session management, authorization/role "
        "definitions, encryption, or trust relationships is made without "
        "triggering a fresh threat/attack surface reassessment."
    ),
    "negative_access_model_risk": (
        "The application uses a negative (default-allow) access model, where a "
        "mistake in permission definitions is hard to detect, rather than a "
        "positive (default-deny) model."
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
