"""Forgot Password Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Forgot Password Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python forgot_password_classifier.py "some text to classify"
    python forgot_password_classifier.py --file path/to/content.txt
    echo "some text" | python forgot_password_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Forgot Password Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Forgot_Password_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's guidance on the forgot-password
# request step, the reset step, URL tokens, PINs, security questions, and
# account lockout.
CATEGORIES = {
    "user_enumeration_via_inconsistent_response": (
        "The forgot-password endpoint returns a different message, response "
        "code, or timing for an existing account versus a non-existing one, "
        "letting an attacker enumerate valid usernames/emails."
    ),
    "weak_reset_token_generation": (
        "The password reset token or code is not generated with a "
        "cryptographically secure random algorithm, is too short to resist "
        "brute-forcing, or is reusable/does not expire."
    ),
    "missing_rate_limiting_on_reset_requests": (
        "There is no rate limiting or CAPTCHA on the forgot-password "
        "request endpoint, allowing an attacker to trigger thousands of "
        "reset emails/SMS messages for a target account."
    ),
    "premature_account_modification": (
        "The account is locked, modified, or otherwise changed before a "
        "valid reset token/code has been presented and verified."
    ),
    "insecure_reset_url_handling": (
        "The password reset URL is built using the untrusted Host header "
        "(host header injection risk), is served over plain HTTP, or the "
        "reset page is missing a Referrer-Policy: noreferrer to prevent "
        "referrer leakage of the token."
    ),
    "weak_pin_based_reset": (
        "A PIN-based reset flow uses a PIN that is too short, not rate-"
        "limited, or otherwise practical to brute-force before a restricted "
        "session is created from it."
    ),
    "insufficient_post_reset_confirmation": (
        "After a password reset, the user is not notified by email, is "
        "automatically logged in instead of going through normal login, or "
        "is not given the option to invalidate other existing sessions."
    ),
    "overreliance_on_security_questions": (
        "Security questions are used as the sole or primary mechanism to "
        "reset a password, rather than as an additional factor alongside "
        "other reset methods."
    ),
    "account_lockout_denial_of_service": (
        "An account gets locked out purely because of repeated forgot-"
        "password attempts, which an attacker could exploit to deny access "
        "to a legitimate user who has a known username."
    ),
    "inconsistent_password_policy_enforcement": (
        "The password-reset flow allows setting a new password that does not "
        "meet the same complexity/security policy enforced elsewhere in the "
        "application."
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
