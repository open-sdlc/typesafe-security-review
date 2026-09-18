"""Logging Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Logging Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python logging_classifier.py "some text to classify"
    python logging_classifier.py --file path/to/content.txt
    echo "some text" | python logging_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Logging Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_security_event_logging": (
        "A security-relevant event goes unlogged, such as an authentication "
        "success/failure, an authorization failure, an input/output "
        "validation failure, or use of higher-risk functionality (e.g. "
        "admin actions, key rotation, data export)."
    ),
    "sensitive_data_in_logs": (
        "Data that should be excluded, masked, or encrypted is written "
        "directly into logs, such as passwords, session tokens, encryption "
        "keys, or payment cardholder data."
    ),
    "log_injection_via_unsanitized_input": (
        "Untrusted event data is written into a log entry without "
        "sanitization, allowing carriage-return/line-feed (CRLF) or "
        "delimiter injection that forges additional or misleading log "
        "entries."
    ),
    "insufficient_log_event_attributes": (
        "A log entry is missing key 'when/where/who/what' attributes "
        "needed for investigation, such as an accurate timestamp, source "
        "address, user identity, action, or result status."
    ),
    "insecure_log_storage_or_transmission": (
        "Logs are stored or transmitted without appropriate access "
        "control, integrity protection (tamper detection), or a secure "
        "transport protocol when sent to a centralized system."
    ),
    "log_availability_dos_risk": (
        "An attacker (or a bug) can flood the logging mechanism to exhaust "
        "disk space or database transaction log space, causing a denial of "
        "service for the application or its logging."
    ),
    "inadequate_log_retention_or_disposal": (
        "Log data, temporary debug logs, or backups are destroyed before, "
        "or retained beyond, the duration required by a legal, regulatory, "
        "or contractual retention obligation."
    ),
    "missing_log_monitoring_alerting": (
        "Collected log data is not integrated into active monitoring, "
        "alerting, or incident-response processes, so serious events are "
        "not signaled to the responsible teams."
    ),
    "log_confidentiality_or_integrity_attack": (
        "Content describes an attacker reading logs to exfiltrate secrets/"
        "PII, or tampering with, deleting, or falsifying log entries to "
        "cover their tracks or frame another party."
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
