"""Access Control Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Access Control Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html

NOTE: The live page is a deprecated stub ('DEPRECATED: Access Control
Cheatsheet') that contains only a redirect to the Authorization Cheat
Sheet and no substantive content of its own. Categories below are
instead derived from OWASP's well-established Broken Access Control
(A01:2021) domain knowledge, focused on classic access-control attack
patterns and kept distinct from the policy-model-focused Authorization
Cheat Sheet classifier.

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python access_control_classifier.py "some text to classify"
    python access_control_classifier.py --file path/to/content.txt
    echo "some text" | python access_control_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Access Control Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "idor_direct_object_reference": (
        "An attacker accesses or modifies another user's data or resource by "
        "directly manipulating an object reference or identifier (e.g. an ID in a "
        "URL or API parameter) without a server-side ownership check (Insecure "
        "Direct Object Reference)."
    ),
    "forced_browsing": (
        "An attacker reaches a restricted URL, admin panel, or API endpoint by "
        "directly requesting or guessing its path, bypassing navigation links "
        "that would normally be hidden from unauthorized users."
    ),
    "vertical_privilege_escalation": (
        "A lower-privileged user gains access to administrative functionality or "
        "data reserved for a higher-privileged role."
    ),
    "horizontal_privilege_escalation": (
        "An authenticated user accesses or modifies another user's resource at "
        "the same privilege level, without authorization to do so."
    ),
    "missing_function_level_access_control": (
        "A server-side function or endpoint omits an access-control check "
        "entirely, relying instead on the client-side UI to hide the "
        "corresponding button or menu item."
    ),
    "cors_misconfiguration": (
        "An overly permissive Cross-Origin Resource Sharing configuration (e.g. "
        "reflecting any Origin with credentials allowed) lets an unauthorized "
        "origin read authenticated responses."
    ),
    "parameter_or_cookie_tampering_for_access": (
        "A user modifies a hidden form field, cookie, or request parameter (e.g. "
        "setting role=admin) to gain unauthorized access to a function or "
        "resource."
    ),
    "exposed_backup_or_metadata": (
        "Sensitive backup files, directory listings, or configuration metadata "
        "are reachable because access restrictions were not applied to them."
    ),
    "missing_rate_limit_on_protected_resource": (
        "A sensitive, access-controlled resource or login mechanism lacks rate "
        "limiting or lockout, allowing brute-force attempts to guess credentials "
        "or valid object identifiers."
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
