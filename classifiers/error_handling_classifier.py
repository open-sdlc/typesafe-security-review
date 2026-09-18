"""Error Handling Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Error Handling Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python error_handling_classifier.py "some text to classify"
    python error_handling_classifier.py --file path/to/content.txt
    echo "some text" | python error_handling_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Error Handling Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Error_Handling_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's discussion of reconnaissance via
# unhandled errors, and its per-framework global error handler proposals
# (generic response to the user, detailed logging server-side, RFC 7807).
CATEGORIES = {
    "stack_trace_disclosure": (
        "A raw exception stack trace (e.g. Java/.NET framework or server "
        "internals, class names, line numbers) is rendered directly in an "
        "HTTP response instead of a generic error message."
    ),
    "verbose_database_error_disclosure": (
        "A database driver or ORM error message (e.g. SQL syntax errors, "
        "ODBC/JDBC warnings) is shown to the user, revealing query structure, "
        "table/column names, or server file paths."
    ),
    "missing_global_error_handler": (
        "The application has no centralized/global exception handler "
        "configured at the runtime or framework level, so unexpected errors "
        "are not consistently caught and converted to a safe response."
    ),
    "inconsistent_http_status_usage": (
        "Error responses use the wrong class of HTTP status code, e.g. "
        "returning a 5xx for a client-caused failure or vice versa, instead "
        "of matching the failure mode to the correct status code."
    ),
    "sensitive_data_in_error_logs": (
        "Error logging includes sensitive data (credentials, tokens, PII) "
        "alongside the exception details, or fails to follow secure logging "
        "practices when recording the error server-side."
    ),
    "information_leakage_aiding_reconnaissance": (
        "An unhandled or misconfigured error reveals technical details "
        "(application server name/version, framework, library versions, "
        "installation paths) that would help an attacker's reconnaissance "
        "phase."
    ),
    "lack_of_standardized_error_format": (
        "API error responses are not returned in a consistent, structured "
        "format such as RFC 7807 Problem Details, making errors inconsistent "
        "across endpoints and harder to safely handle."
    ),
    "injection_point_identification_via_errors": (
        "An error message resulting from malformed or malicious input (e.g. "
        "a type conversion or SQL error) inadvertently reveals a potential "
        "injection point to an attacker probing the application."
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
