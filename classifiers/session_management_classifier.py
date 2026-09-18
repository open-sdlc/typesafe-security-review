"""Session Management Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Session Management Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python session_management_classifier.py "some text to classify"
    python session_management_classifier.py --file path/to/content.txt
    echo "some text" | python session_management_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Session Management Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Session_Management_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's session ID property and session
# management implementation sections. Each description is written so Jev (the
# TypeSafe model) can distinguish it from neighboring categories -- be
# specific about what does and does not count.
CATEGORIES = {
    "weak_session_id_entropy": (
        "The session identifier is generated with insufficient randomness or without a "
        "cryptographically secure pseudorandom number generator (CSPRNG), falling short of "
        "the recommended 64+ bits of entropy needed to resist brute-force guessing."
    ),
    "session_id_in_url": (
        "The session ID is exchanged via a mechanism other than cookies, such as a URL "
        "parameter, GET query string, or hidden form field, risking disclosure through "
        "browser history, logs, bookmarks, or the Referer header."
    ),
    "session_id_information_disclosure": (
        "The session ID's value itself is descriptive or encodes meaningful data (user "
        "identity, role, or other business/session details) instead of being a meaningless "
        "opaque token, letting an attacker decode application internals from it."
    ),
    "missing_transport_encryption": (
        "The session ID is transmitted over an unencrypted HTTP connection at any point in "
        "the session, or the site mixes encrypted and unencrypted content, exposing the "
        "session token to network eavesdropping."
    ),
    "missing_secure_cookie_attribute": (
        "A session cookie is set without the 'Secure' attribute, meaning it could be sent "
        "over a non-HTTPS channel even though the site supports TLS."
    ),
    "session_fixation": (
        "An attacker is able to set, inject, or predict a victim's session ID before "
        "authentication (session fixation), then hijack the session once the victim logs "
        "in with that same identifier."
    ),
    "framework_default_session_name": (
        "The application uses the web framework's default, easily fingerprinted session "
        "cookie name (e.g. PHPSESSID, JSESSIONID, ASP.NET_SessionId), disclosing the "
        "underlying technology stack to an attacker."
    ),
    "session_hijacking_via_disclosure": (
        "A session ID has been disclosed, captured, predicted, or brute-forced, allowing an "
        "attacker to fully impersonate the victim user by reusing that identifier "
        "(session hijacking/sidejacking)."
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
