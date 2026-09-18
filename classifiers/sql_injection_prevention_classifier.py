"""SQL Injection Prevention Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"SQL Injection Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python sql_injection_prevention_classifier.py "some text to classify"
    python sql_injection_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python sql_injection_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "SQL Injection Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "dynamic_query_concatenation": (
        "A SQL query is built by concatenating a raw string with unvalidated user "
        "input (e.g. 'SELECT ... WHERE user_name = ' + request.getParameter(...)) "
        "rather than using parameter binding."
    ),
    "missing_prepared_statement_or_bind_variable": (
        "Database code executes a query without using a prepared statement, bind "
        "variable, or named-parameter API, so the database cannot distinguish "
        "user-supplied data from SQL code."
    ),
    "unsafe_dynamic_stored_procedure": (
        "A stored procedure constructs SQL dynamically at runtime (e.g. via "
        "sp_executesql, EXEC, or EXECUTE IMMEDIATE) by concatenating unvalidated "
        "input instead of binding it as a parameter."
    ),
    "unvalidated_identifier_substitution": (
        "User input is used directly to select a table name, column name, or sort "
        "direction rather than being mapped through an allow-list/switch of legal "
        "values -- a case bind variables cannot cover."
    ),
    "reliance_on_manual_escaping": (
        "The only defense described against SQL injection is manually escaping "
        "special characters in user input, rather than prepared statements, "
        "stored procedures, or allow-list validation."
    ),
    "hql_orm_injection": (
        "An ORM or query-language layer (e.g. Hibernate HQL) is given a hand- "
        "built query string containing unvalidated user input instead of using "
        "named parameters or the Criteria API."
    ),
    "excessive_database_account_privilege": (
        "A database account used by the application is granted broader rights "
        "than required (e.g. DBA/db_owner, or write access when only read is "
        "needed), amplifying the impact of any successful injection."
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
