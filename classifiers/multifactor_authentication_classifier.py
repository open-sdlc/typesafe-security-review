"""Multifactor Authentication Cheat Sheet classifier built on the TypeSafe
System One API.

Classifies input text against sub-categories drawn from the OWASP
"Multifactor Authentication Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python multifactor_authentication_classifier.py "some text to classify"
    python multifactor_authentication_classifier.py --file path/to/content.txt
    echo "some text" | python multifactor_authentication_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Multifactor Authentication Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Multifactor_Authentication_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "single_factor_masquerading_as_mfa": (
        "Multiple credentials of the same authentication factor type are "
        "required (e.g. both a password and a PIN, both 'something you "
        "know'), which does not constitute true multi-factor authentication "
        "and offers little additional security."
    ),
    "weak_otp_handling": (
        "One-time passwords lack a short time-to-live, are reusable, allow "
        "unlimited verification attempts, are logged in plaintext, or are not "
        "generated with a cryptographically secure random number generator."
    ),
    "insecure_mfa_reset_or_recovery": (
        "The process to reset or recover a lost MFA factor is weak enough "
        "that an attacker could exploit it to bypass MFA and take over an "
        "account, e.g. without rigorous identity verification."
    ),
    "insecure_factor_change_process": (
        "Enrolling or changing an MFA factor (new phone number, new "
        "authenticator, new hardware token) is allowed without requiring "
        "reauthentication with an existing factor or without notifying the "
        "user out-of-band."
    ),
    "deprecated_weak_factor_reliance": (
        "The system relies on a factor no longer considered acceptable, such "
        "as security questions, as an authentication or account-recovery "
        "mechanism."
    ),
    "incomplete_mfa_coverage": (
        "MFA is enforced on the main login flow but not on every way a user "
        "can authenticate, such as a separate API, a mobile application, or "
        "an alternate login endpoint."
    ),
    "missing_step_up_for_sensitive_actions": (
        "MFA or re-authentication is not required before performing sensitive "
        "actions such as changing a password/email, disabling MFA, or "
        "elevating to an administrative session."
    ),
    "third_party_mfa_dependency_risk": (
        "The application depends on a third-party MFA-as-a-service provider "
        "whose compromise could allow an attacker to bypass MFA across all "
        "applications using that service."
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
