"""Logging Vocabulary Cheat Sheet classifier built on the TypeSafe System One
API.

Classifies input text against sub-categories drawn from the OWASP
"Application Logging Vocabulary Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python logging_vocabulary_classifier.py "some text to classify"
    python logging_vocabulary_classifier.py --file path/to/content.txt
    echo "some text" | python logging_vocabulary_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Logging Vocabulary Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Logging_Vocabulary_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "authentication_event_logging": (
        "Content relates to logging an authentication event using the "
        "AUTHN_* vocabulary, such as login success/failure, lockout after "
        "max retries, a password change, or an 'impossible travel' anomaly "
        "between two distant login locations."
    ),
    "authorization_event_logging": (
        "Content relates to logging an authorization event using the "
        "AUTHZ_* vocabulary, such as an access-denied failure, a change to "
        "a user's entitlements, or an action taken by a privileged/admin "
        "user."
    ),
    "cryptographic_operation_failure_logging": (
        "Content relates to logging a failed encryption or decryption "
        "operation using the CRYPT_* vocabulary, which may indicate a "
        "system error or an authorization failure on protected data."
    ),
    "excessive_use_rate_limit_logging": (
        "Content relates to logging that a user or service exceeded a "
        "defined request-rate or concurrent-session ceiling, using the "
        "EXCESS_* vocabulary (e.g. rate_limit_exceeded, sessions_exceeded)."
    ),
    "file_upload_event_logging": (
        "Content relates to logging a file-upload lifecycle event using the "
        "UPLOAD_* vocabulary, such as upload completion, storage/renaming, "
        "virus-scan validation result, or deletion."
    ),
    "input_validation_failure_logging": (
        "Content relates to logging a server-side input validation failure "
        "using the INPUT_* vocabulary, especially a failure against a "
        "discrete/allow-list of options which strongly indicates client-"
        "side tampering."
    ),
    "malicious_behavior_detection_logging": (
        "Content relates to logging an indicator of active attack using the "
        "MALICIOUS_* vocabulary, such as excessive 404s (force-browsing), a "
        "known attack-tool signature, a SQL-injection pattern match, an "
        "illegal CORS request, a direct-object-reference probe, a missing "
        "CSRF token, or a CSP violation report."
    ),
    "mcp_security_event_logging": (
        "Content relates to logging an MCP (Model Context Protocol) "
        "specific security event using the MCP_* vocabulary, such as "
        "detected prompt injection, resource/token-budget exhaustion, or "
        "tool poisoning/tampering."
    ),
    "sensitive_data_access_logging": (
        "Content relates to logging creation, read, update, or deletion of "
        "sensitive or regulated data using the DATA_* vocabulary (e.g. "
        "sensitive_create, sensitive_read, sensitive_update, "
        "sensitive_delete)."
    ),
    "privilege_change_logging": (
        "Content relates to logging a change in file or object permission "
        "levels using the PRIVILEGE_* vocabulary, distinct from user-account "
        "role/entitlement changes covered under authorization."
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
