"""Third Party Javascript Management Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Third Party Javascript Management Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python third_party_javascript_management_classifier.py "some text to classify"
    python third_party_javascript_management_classifier.py --file path/to/content.txt
    echo "some text" | python third_party_javascript_management_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Third Party Javascript Management Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Third_Party_Javascript_Management_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "Major risks" (loss of control,
# arbitrary code execution, data disclosure) and deployment architecture /
# defense sections. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "vendor_server_compromise": (
        "The third-party JavaScript vendor's own server or hosting infrastructure is "
        "compromised, resulting in malicious JavaScript being injected into the tag that "
        "the host site loads and executes."
    ),
    "uncontrolled_third_party_code_change": (
        "The third-party vendor pushes new features or changes to the hosted JavaScript at "
        "any time without the host's review, potentially breaking the interface, data flow, "
        "or availability of the host application unexpectedly."
    ),
    "arbitrary_code_execution_via_tag": (
        "Third-party JavaScript executes on the client with the full privileges granted to "
        "the host page without prior review, similar to an XSS attack, because the code was "
        "not audited before integration."
    ),
    "sensitive_data_leakage_to_vendor": (
        "Loading a third-party tag causes the browser to send sensitive information -- IP "
        "address, referrer, cookies, or DOM data -- directly to the third-party server, "
        "enabling user tracking or profiling beyond what the host intended."
    ),
    "missing_subresource_integrity": (
        "A third-party script is loaded via a <script src=...> reference without a "
        "Subresource Integrity (SRI) hash, so the browser cannot detect if the fetched file "
        "was tampered with in transit or at the source."
    ),
    "tag_manager_container_risk": (
        "A tag manager's container JavaScript (loaded via a snippet like Google Tag "
        "Manager's dataLayer script) can be reconfigured through a non-technical GUI to run "
        "arbitrary new marketing/analytics code without a code review or deployment step."
    ),
    "unvalidated_dom_data_access": (
        "Third-party tag JavaScript is allowed to read directly from arbitrary DOM elements "
        "or URL parameters (rather than being confined to a vetted, host-defined data "
        "layer), risking injection of unvalidated data into the tracking pipeline."
    ),
    "expired_or_abandoned_vendor_domain": (
        "The domain hosting the third-party JavaScript has expired, been abandoned, or the "
        "maintaining company has gone out of business, creating a risk that an attacker "
        "re-registers the domain and serves malicious code from the same script URL."
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
