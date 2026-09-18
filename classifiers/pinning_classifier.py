"""Pinning Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Pinning Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python pinning_classifier.py "some text to classify"
    python pinning_classifier.py --file path/to/content.txt
    echo "some text" | python pinning_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Pinning Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Pinning_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's guidance on when/what/how to
# pin certificates and public keys. Each description is written so Jev (the
# TypeSafe model) can distinguish it from neighboring categories -- be
# specific about what does and does not count.
CATEGORIES = {
    "inappropriate_pinning_decision": (
        "Certificate/public key pinning is implemented in a situation where "
        "it is not warranted, such as when the client doesn't control both "
        "ends of the connection, the pinset can't be securely updated, or the "
        "application is not a native mobile app."
    ),
    "root_ca_pinning_overreach": (
        "The application pins the root Certificate Authority instead of a "
        "leaf certificate or intermediate CA, which implicitly trusts every "
        "other certificate issued by that root and its sub-CAs."
    ),
    "missing_backup_pin": (
        "Only a single leaf certificate or key is pinned with no backup pin "
        "(e.g. an intermediate CA or alternate key), risking the application "
        "being bricked/unable to connect when the certificate rotates."
    ),
    "undisclosed_interception_proxy_allowlist": (
        "An interception/DLP proxy's certificate is allow-listed or excluded "
        "from pin validation without explicit instruction from a risk "
        "acceptance process, defeating the pinning security goal silently."
    ),
    "diy_pin_validation_implementation": (
        "Pin validation logic (certificate/public key comparison in the "
        "TLS callback) is implemented from scratch rather than using a "
        "vetted platform mechanism or library, risking subtle implementation "
        "mistakes that lead to bypassable checks."
    ),
    "unmanageable_pinset_update_mechanism": (
        "The application has no secure, reliable way to update its pinset "
        "when a pinned certificate or key rotates, other than a disruptive "
        "full application redeployment, risking a hard outage."
    ),
    "weak_pin_target_selection": (
        "The application pins a bare hash/fingerprint of the certificate or "
        "key rather than the full certificate or `subjectPublicKeyInfo`, "
        "losing access to contextual information like the algorithm or OID "
        "needed to properly validate the key."
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
