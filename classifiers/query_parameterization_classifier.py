"""Query Parameterization Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Query Parameterization Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python query_parameterization_classifier.py "some text to classify"
    python query_parameterization_classifier.py --file path/to/content.txt
    echo "some text" | python query_parameterization_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Query Parameterization Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "string_concatenation_query_building": (
        "A SQL statement is assembled by concatenating raw strings with user- "
        "supplied input (e.g. 'SELECT ... WHERE name = ' + userInput) instead of "
        "using bind parameters or placeholders."
    ),
    "missing_prepared_statement": (
        "Database access code executes a query without a prepared statement / "
        "parameterized query API (e.g. no PreparedStatement, no parameter "
        "placeholders like '?' or ':name', no .bindParam()/.setString() calls)."
    ),
    "client_side_only_parameterization": (
        "Query parameterization or placeholder substitution happens only in a "
        "client-side library or framework, which then sends an already- "
        "concatenated raw query string to the server, rather than parameterizing "
        "server-side."
    ),
    "unsafe_dynamic_stored_procedure": (
        "A stored procedure builds a SQL statement dynamically (e.g. via EXECUTE "
        "IMMEDIATE, sp_executesql, EXEC) by concatenating input rather than "
        "binding it as a parameter to the dynamic statement."
    ),
    "unbindable_identifier_substitution": (
        "User input is used to select a table name, column name, or sort order "
        "(ASC/DESC) -- values that cannot be parameterized with bind variables "
        "and instead require allow-list validation."
    ),
    "orm_query_language_injection": (
        "An ORM/query-language layer (HQL, Criteria API, ActiveRecord conditions) "
        "is given a hand-built query string containing unvalidated user input "
        "rather than using named parameters or the query builder's parameter "
        "binding."
    ),
    "excessive_stored_procedure_privilege": (
        "Discussion of stored procedures requiring elevated execute rights (e.g. "
        "db_owner) beyond the read/write access the application actually needs, "
        "increasing the impact of any injected or abused query."
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
