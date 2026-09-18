"""Cookie Theft Mitigation Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Cookie Theft Mitigation Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python cookie_theft_mitigation_classifier.py "some text to classify"
    python cookie_theft_mitigation_classifier.py --file path/to/content.txt
    echo "some text" | python cookie_theft_mitigation_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Cookie Theft Mitigation Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Cookie_Theft_Mitigation_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "stolen_session_cookie_replay": (
        "A session cookie obtained through malware, phishing, or another "
        "means is replayed by an attacker from a different device to hijack "
        "the victim's authenticated session for the remaining validity "
        "period of that cookie."
    ),
    "missing_ip_address_change_detection": (
        "The application does not compare the IP address (or its geolocation) "
        "used to establish a session against the IP address used on "
        "subsequent requests, missing a signal that could reveal session "
        "hijacking."
    ),
    "missing_user_agent_change_detection": (
        "The application does not track or compare the User-Agent header "
        "associated with a session, missing a signal that the session cookie "
        "is now being used from a different browser or device than the one "
        "that created it."
    ),
    "missing_accept_language_or_client_hints_check": (
        "The application ignores auxiliary request signals such as "
        "Accept-Language or Client Hint headers (sec-ch-ua*, Sec-Fetch-*) that "
        "could help detect a session being used from an unexpected "
        "environment."
    ),
    "false_positive_legitimate_environment_change": (
        "A legitimate user's normal behavior, such as traveling to a new "
        "country or updating their browser, is misclassified as session "
        "hijacking because the detection logic treats any environment change "
        "as suspicious without nuance."
    ),
    "false_negative_same_region_attacker": (
        "An attacker uses the stolen session cookie from the same country or "
        "network as the victim, evading IP-Geo based hijacking detection that "
        "only flags cross-region changes."
    ),
    "missing_reauthentication_on_suspected_hijack": (
        "When a suspected session hijack is detected, the application does "
        "not invalidate the session and force re-authentication (or a "
        "CAPTCHA challenge) before allowing continued or sensitive access."
    ),
    "absent_sender_constrained_session_token": (
        "The session cookie is a simple bearer token with no cryptographic "
        "binding to the issuing device/browser (such as Device Bound Session "
        "Credentials), so anyone possessing the cookie value can impersonate "
        "the user."
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
