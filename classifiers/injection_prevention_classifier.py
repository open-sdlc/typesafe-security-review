"""Injection Prevention Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Injection Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python injection_prevention_classifier.py "some text to classify"
    python injection_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python injection_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Injection Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Injection_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "sql_injection": (
        "SQL injection: untrusted input is incorporated into a SQL query in a "
        "way that alters its logic, including inband attacks (results returned "
        "directly), blind/inferential attacks (boolean or time-delay based, e.g. "
        "sleep()-style conditionals), or out-of-band attacks (data exfiltrated "
        "via a separate channel such as DNS or email)."
    ),
    "stored_procedure_injection": (
        "Dynamic SQL is built and executed inside a database stored procedure "
        "using unsanitized user input, letting an attacker inject malicious SQL "
        "through the procedure itself rather than the calling application code."
    ),
    "ldap_injection": (
        "Untrusted input is used to construct an LDAP search filter or "
        "distinguished name (DN) without proper escaping, allowing an attacker "
        "to alter directory queries, bypass authentication, or read/modify "
        "unauthorized directory entries."
    ),
    "xpath_injection": (
        "Untrusted input is concatenated into an XPath query evaluated against "
        "an XML document, allowing an attacker to alter the query's logic or "
        "extract data outside the intended node set."
    ),
    "scripting_eval_injection": (
        "Untrusted input is passed to a scripting language's eval-like dynamic "
        "code execution feature, letting an attacker execute arbitrary code at "
        "runtime rather than having it treated as inert data."
    ),
    "os_command_injection": (
        "Untrusted input (e.g. from a web parameter) is used to build and "
        "execute an operating system command, letting an attacker append or "
        "inject additional shell commands, such as via a semicolon or other "
        "command separator."
    ),
    "prepared_statement_or_stored_procedure_defense": (
        "The content discusses using prepared statements/parameterized queries "
        "(e.g. Java PreparedStatement/CallableStatement) or a safely implemented "
        "stored procedure as the primary defense that keeps attacker input from "
        "changing a query's intent."
    ),
    "allowlist_validation_defense": (
        "The content discusses allow-list input validation as a defense for "
        "query elements that cannot be parameterized, such as table/column "
        "names or a sort-order (ASC/DESC) indicator."
    ),
    "escaping_last_resort_defense": (
        "The content discusses escaping untrusted input before including it in "
        "a query as a frail, last-resort mitigation used mainly to retrofit "
        "legacy code when parameterization or input validation isn't feasible."
    ),
    "legacy_closed_source_remediation": (
        "The content discusses handling injection flaws in a productive, "
        "closed-source, or otherwise hard-to-modify legacy application where "
        "fixing the source code directly is not possible, e.g. via virtual "
        "patching."
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
