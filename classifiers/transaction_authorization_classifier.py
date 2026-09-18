"""Transaction Authorization Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Transaction Authorization Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python transaction_authorization_classifier.py "some text to classify"
    python transaction_authorization_classifier.py --file path/to/content.txt
    echo "some text" | python transaction_authorization_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Transaction Authorization Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Transaction_Authorization_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's functional and non-functional
# guidelines sections. Each description is written so Jev (the TypeSafe
# model) can distinguish it from neighboring categories -- be specific about
# what does and does not count.
CATEGORIES = {
    "insufficient_transaction_data_confirmation": (
        "The authorization mechanism does not let the user identify and acknowledge the "
        "significant data of the transaction being authorized (e.g. target account and "
        "amount), violating the 'What You See Is What You Sign' principle."
    ),
    "unauthorized_auth_method_change": (
        "A user's transaction authorization token or authorization method can be changed "
        "without requiring confirmation via the user's current, still-valid authorization "
        "credential or method."
    ),
    "authentication_authorization_conflation": (
        "The same method or credential (e.g. a single OTP scheme) is used for both user "
        "authentication and transaction authorization, letting malware trick a user into "
        "supplying two codes -- one for login and one that unknowingly authorizes fraud."
    ),
    "reused_or_predictable_credentials": (
        "Transaction authorization credentials (OTPs, codes, tokens) are reusable across "
        "multiple transactions, valid for the entire session, or otherwise not unique per "
        "operation, enabling replay by an attacker who captured one valid code."
    ),
    "client_side_authorization_enforcement": (
        "Transaction authorization decisions, transaction verification data, or checks are "
        "generated or enforced on the client instead of exclusively on the server, allowing "
        "tampering with parameters to bypass or falsify the authorization result."
    ),
    "authorization_credential_brute_forcing": (
        "Submitted authorization credentials (e.g. OTP codes) can be attempted repeatedly "
        "without lockout or restart of the authorization process, enabling brute-force "
        "guessing."
    ),
    "transaction_state_transition_bypass": (
        "The multi-step transaction authorization flow (data entry, request, challenge, "
        "confirmation, credential submission, execution) can be performed out of order or "
        "with steps skipped entirely."
    ),
    "toctou_transaction_data_tampering": (
        "Transaction data can be modified or replaced by malware after the user entered "
        "and confirmed it but before final execution, without invalidating the previously "
        "issued authorization (time-of-check to time-of-use)."
    ),
    "unbounded_credential_validity_window": (
        "An authorization credential, challenge, or OTP remains valid indefinitely or for "
        "an excessively long time rather than expiring shortly after issuance, allowing "
        "delayed use from an attacker-controlled machine."
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
