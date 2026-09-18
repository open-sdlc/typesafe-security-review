"""NoSQL Security Cheat Sheet classifier built on the TypeSafe System One
API.

Classifies input text against sub-categories drawn from the OWASP
"NoSQL Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python nosql_security_classifier.py "some text to classify"
    python nosql_security_classifier.py --file path/to/content.txt
    echo "some text" | python nosql_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "NoSQL Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "NoSQL_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "Threats & Common Failure
# Modes" section and its practical defenses. Each description is written so
# Jev (the TypeSafe model) can distinguish it from neighboring categories --
# be specific about what does and does not count.
CATEGORIES = {
    "nosql_query_injection": (
        "A NoSQL query object or string is built by concatenating or "
        "`eval`-ing untrusted input, or the client is allowed to submit "
        "operators like `$where`, `$regex`, or `$expr` that change query "
        "semantics or execute code."
    ),
    "exposed_management_interface": (
        "An admin GUI, database port, or REST management endpoint for the "
        "NoSQL database is reachable from the public Internet instead of "
        "being restricted to an internal admin network."
    ),
    "weak_or_missing_authentication": (
        "The NoSQL database runs with authentication disabled entirely, uses "
        "default accounts/passwords, or grants clients excessive privileges "
        "beyond least privilege."
    ),
    "insecure_network_exposure": (
        "The database is bound to a public interface (e.g. 0.0.0.0) instead "
        "of an internal one, lacks TLS encryption in transit for driver or "
        "admin connections, or is not isolated by network segmentation."
    ),
    "insecure_deserialization": (
        "Data read from or written to the NoSQL store is deserialized using "
        "an unsafe object deserialization mechanism, creating a path to "
        "remote code execution."
    ),
    "hardcoded_or_leaked_db_credentials": (
        "Database credentials are hardcoded in source code, baked into "
        "container images, or exposed via CI/CD logs or environment variables "
        "instead of being pulled from a secrets manager."
    ),
    "unencrypted_backup_exposure": (
        "Database backups or snapshots are stored unencrypted, left "
        "publicly accessible, or not validated by regular restore testing."
    ),
    "vulnerable_driver_or_odm_dependency": (
        "The application uses an outdated or vulnerable NoSQL driver, ODM, or "
        "plugin, introducing supply-chain risk into how queries and data are "
        "handled."
    ),
    "insufficient_db_audit_logging": (
        "Connection attempts, admin actions, failed authentication, or "
        "suspicious commands (e.g. `$where`, map-reduce jobs) against the "
        "database are not logged or monitored for anomalies."
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
