"""Database Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Database Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python database_security_classifier.py "some text to classify"
    python database_security_classifier.py --file path/to/content.txt
    echo "some text" | python database_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Database Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "excessive_network_exposure": (
        "The database is reachable over the network more broadly than "
        "necessary, e.g. bound to all interfaces rather than localhost, "
        "lacking firewall restrictions to specific hosts, or not isolated on "
        "a dedicated internal network segment from the application server."
    ),
    "unencrypted_database_transport": (
        "Connections to the database are not required to use TLS 1.2+ with "
        "modern ciphers, or the client does not verify the server's digital "
        "certificate, leaving traffic (including credentials or query data) "
        "exposed in clear text."
    ),
    "weak_or_shared_database_credentials": (
        "Database accounts use weak, default, or shared passwords, or a "
        "single account is shared across multiple applications/services "
        "instead of each service having its own uniquely credentialed "
        "account."
    ),
    "hardcoded_or_unprotected_db_credentials": (
        "Database credentials are stored in application source code, checked "
        "into a source repository, or kept in a configuration file that is "
        "not encrypted or does not have restrictive file permissions."
    ),
    "excessive_database_account_privileges": (
        "A database account is granted more privileges than required for the "
        "application to function, such as administrative/owner rights, use "
        "of built-in root/sa/SYS accounts, or lacking table/column/row-level "
        "restriction where warranted."
    ),
    "default_accounts_or_databases_present": (
        "Default database accounts, sample databases, or out-of-the-box "
        "installations (e.g. not having run mysql_secure_installation) remain "
        "present and were not removed as part of hardening."
    ),
    "insecure_direct_thick_client_access": (
        "A thick client or otherwise untrusted system connects directly to "
        "the backend database instead of going through an API layer capable "
        "of enforcing access control."
    ),
    "missing_patching_or_baseline_hardening": (
        "The database server or its underlying operating system is not kept "
        "up to date with security patches, or is not configured against a "
        "recognized hardening baseline such as CIS Benchmarks."
    ),
    "unprotected_backups_or_transaction_logs": (
        "Database backups or transaction logs are stored without appropriate "
        "permissions or encryption, or are kept on the same disk as the "
        "primary database files rather than separated."
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
