"""Email Validation and Verification Cheat Sheet classifier built on the
TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Email Validation and Verification Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python email_validation_and_verification_classifier.py "some text to classify"
    python email_validation_and_verification_classifier.py --file path/to/content.txt
    echo "some text" | python email_validation_and_verification_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Email Validation and Verification Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Email_Validation_and_Verification_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's threat model and sections on
# canonicalization, format validation, Unicode/IDN, verification, password
# reset, email change, anti-enumeration, disposable email, and MFA.
CATEGORIES = {
    "inconsistent_email_canonicalization": (
        "The application applies inconsistent email normalization/comparison "
        "logic (e.g. provider-specific dot removal, case folding) across "
        "registration, login, password reset, and account linking flows, "
        "risking account confusion or takeover."
    ),
    "weak_format_validation": (
        "Email format validation relies on custom, overly strict, or poorly "
        "tested regular expressions instead of well-tested libraries, causing "
        "valid addresses to be rejected or malformed ones accepted."
    ),
    "unicode_homoglyph_spoofing": (
        "Internationalized domain names or local-parts are not normalized to "
        "punycode/Unicode-normalized form before comparison, allowing "
        "homoglyph spoofing (e.g. Latin vs Cyrillic look-alike characters)."
    ),
    "account_enumeration_risk": (
        "Login, registration, or password-reset responses differ in "
        "message content or timing between existing and non-existing "
        "accounts, letting an attacker enumerate valid registered emails."
    ),
    "insecure_verification_tokens": (
        "Email ownership verification tokens are not cryptographically "
        "random, are reusable, never expire, or the account is activated "
        "before verification completes."
    ),
    "password_reset_flow_weaknesses": (
        "Password reset tokens are not single-use/time-limited, reset "
        "requests are not rate-limited, or the response discloses whether "
        "the submitted email exists in the system."
    ),
    "email_change_workflow_weaknesses": (
        "Changing a user's email address does not require re-authentication, "
        "does not notify the old address, or does not require confirmation "
        "of the new address before the change takes effect."
    ),
    "disposable_email_abuse": (
        "The application has no controls (denylist or risk-based detection) "
        "for disposable/temporary email domains being used to bypass "
        "verification or create abusive accounts."
    ),
    "email_as_weak_authentication_factor": (
        "Email possession alone is treated as a strong authentication factor "
        "for sensitive operations, instead of requiring multi-factor "
        "authentication."
    ),
    "sensitive_email_logging_exposure": (
        "Logs record full, unmasked email addresses, or record verification/"
        "reset tokens or full verification/reset URLs, instead of masking "
        "email addresses and omitting secrets from logs."
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
