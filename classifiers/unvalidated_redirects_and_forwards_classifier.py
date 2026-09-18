"""Unvalidated Redirects and Forwards Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Unvalidated Redirects and Forwards Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python unvalidated_redirects_and_forwards_classifier.py "some text to classify"
    python unvalidated_redirects_and_forwards_classifier.py --file path/to/content.txt
    echo "some text" | python unvalidated_redirects_and_forwards_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Unvalidated Redirects and Forwards Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "Dangerous URL Redirects",
# "Dangerous Forward", and prevention sections. Each description is written
# so Jev (the TypeSafe model) can distinguish it from neighboring categories
# -- be specific about what does and does not count.
CATEGORIES = {
    "open_redirect_via_parameter": (
        "A redirect target URL is taken directly from a user-controlled request parameter "
        "(e.g. a 'url' query string value) and used in a redirect response without any "
        "validation."
    ),
    "phishing_via_trusted_domain_link": (
        "A crafted link uses the trusted, legitimate application's own domain as the "
        "visible host but leverages the app's open redirect to send the victim onward to "
        "an attacker-controlled site, making the phishing attempt appear more credible."
    ),
    "unvalidated_forward_privilege_bypass": (
        "A server-side forward parameter (e.g. 'fwd=admin.jsp') is used to reach a "
        "privileged or administrative function without the application checking that the "
        "user is authorized to access that destination."
    ),
    "continued_execution_after_redirect_header": (
        "Code continues executing on the server after a redirect header is sent (e.g. "
        "missing 'exit'/'die' after a PHP header() redirect), allowing a client that "
        "ignores the redirect to still access page content that should have been skipped."
    ),
    "missing_redirect_target_allowlist": (
        "The application accepts arbitrary redirect or forward destinations instead of "
        "restricting them to an explicit allowlist of trusted hosts, paths, or tokens."
    ),
    "redirect_target_enumeration": (
        "Redirect destinations are referenced by a short ID or token mapped server-side to "
        "a full URL, but the ID space is small or sequential enough that an attacker could "
        "enumerate it to discover all possible redirect targets."
    ),
    "missing_redirect_confirmation_page": (
        "The application redirects a user off-site without first showing an interstitial "
        "warning page that clearly displays the destination and requires the user to "
        "confirm before leaving."
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
