"""GraphQL Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"GraphQL Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python graphql_classifier.py "some text to classify"
    python graphql_classifier.py --file path/to/content.txt
    echo "some text" | python graphql_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "GraphQL Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "GraphQL_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's Input Validation, DoS
# Prevention, Access Control, Batching Attacks, and Secure Configurations
# sections.
CATEGORIES = {
    "injection_via_resolver_input": (
        "User-supplied identifiers or arguments in a GraphQL query/mutation "
        "reach a data fetcher's HTTP, database, or other backend call "
        "without safe parameterization, risking SQL/NoSQL/ORM or command "
        "injection."
    ),
    "unbounded_query_depth_or_amount_dos": (
        "A GraphQL query has unlimited nesting depth or requests an "
        "excessive amount of a paginated object (e.g. millions of items) "
        "because depth limiting, amount limiting, or pagination is not "
        "enforced."
    ),
    "missing_query_cost_or_timeout_controls": (
        "The GraphQL server has no query cost analysis and no "
        "application-level timeout for query/resolver execution, letting an "
        "expensive query consume excessive server resources."
    ),
    "missing_rate_limiting": (
        "GraphQL requests are not rate-limited per IP or per user, allowing "
        "a single client to flood the API with requests."
    ),
    "broken_object_level_authorization": (
        "A query accesses an object directly via its ID (including through "
        "node/nodes fields) without verifying the caller is authorized to "
        "view or modify that specific object (GraphQL IDOR)."
    ),
    "excessive_field_level_data_exposure": (
        "The schema exposes sensitive fields to all consumers without a "
        "per-field access check, letting unauthorized callers fetch data "
        "they should not see."
    ),
    "unauthorized_mutation_access": (
        "A mutation that modifies or deletes data lacks an access-control "
        "check, allowing a caller without appropriate permissions to change "
        "data through the API."
    ),
    "batching_brute_force_attack": (
        "A single GraphQL request batches many queries or object instances "
        "(aliased fields) to enumerate objects or brute-force credentials/"
        "OTPs/session tokens in a way that evades per-request rate limits "
        "and security tooling."
    ),
    "insecure_introspection_or_graphiql_exposure": (
        "Introspection queries or the GraphiQL explorer are left enabled and "
        "unauthenticated in a production/publicly accessible environment, "
        "revealing the full schema."
    ),
    "verbose_error_disclosure": (
        "The GraphQL server returns excessive error detail such as stack "
        "traces or debug information instead of generic error messages."
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
