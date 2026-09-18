"""Authentication Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Authentication Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python authentication_classifier.py "some text to classify"
    python authentication_classifier.py --file path/to/content.txt
    echo "some text" | python authentication_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Authentication Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "weak_password_policy": (
        "A password policy allows weak passwords -- too short a minimum length "
        "for the given MFA state, no blocklist/breach screening, or mandatory "
        "composition rules and periodic forced rotation used in place of length "
        "and blocklist checks."
    ),
    "insecure_password_comparison_or_storage": (
        "Passwords are stored or compared unsafely -- without a secure hashing "
        "algorithm, without a constant-time comparison function, or without "
        "explicit type-safety guarding against type-confusion issues."
    ),
    "account_enumeration_via_responses": (
        "Login, registration, or password-recovery responses (or their timing) "
        "differ based on whether a username/account exists, is locked, or the "
        "password was merely wrong, letting an attacker enumerate valid accounts."
    ),
    "missing_reauthentication_for_sensitive_action": (
        "A sensitive operation, such as changing a password/email or a high-risk "
        "transaction, is performed without re-verifying the user's current "
        "credentials or requiring step-up authentication."
    ),
    "insecure_credential_transport": (
        "A login page or an authenticated session is served without TLS or "
        "another strong transport, exposing credentials or the session identifier "
        "to interception."
    ),
    "missing_or_weak_mfa": (
        "Multi-factor authentication is absent, optional where it should be "
        "required, or otherwise weak/bypassable for sensitive accounts or after a "
        "high-risk event."
    ),
    "predictable_user_identifiers": (
        "User IDs are sequential or otherwise predictable rather than randomly "
        "generated, enabling an attacker to infer or enumerate valid identifiers."
    ),
    "sensitive_account_on_public_interface": (
        "A sensitive/internal account (used for backend, middleware, or database "
        "access) can log in through a public-facing front-end interface, or the "
        "same authentication solution used internally is exposed for unsecured "
        "public access."
    ),
    "missing_risk_based_reauthentication": (
        "The application fails to trigger adaptive re-authentication or MFA after "
        "high-risk events such as suspicious login patterns, new device "
        "enrollment, or account recovery."
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
