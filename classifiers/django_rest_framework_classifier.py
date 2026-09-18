"""Django REST Framework Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Django REST Framework Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/Django_REST_Framework_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python django_rest_framework_classifier.py "some text to classify"
    python django_rest_framework_classifier.py --file path/to/content.txt
    echo "some text" | python django_rest_framework_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Django REST Framework Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Django_REST_Framework_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's OWASP API Security Top 10
# (2019) walkthrough as applied to Django REST Framework (DRF) settings.
CATEGORIES = {
    "broken_object_level_authorization": (
        "A DRF view retrieves or modifies an object by primary key/ID without "
        "calling check_object_permissions(request, obj), or overrides "
        "get_object() without verifying the requesting user should have "
        "access to that specific object (IDOR at the object level)."
    ),
    "broken_authentication": (
        "DEFAULT_AUTHENTICATION_CLASSES is missing, misconfigured, or an "
        "endpoint overrides authentication_classes so that a non-public API "
        "endpoint can be reached without proper authentication."
    ),
    "excessive_data_exposure": (
        "A serializer (especially one inheriting from ModelSerializer) uses "
        "Meta.exclude or otherwise returns more fields than the client needs, "
        "leaking internal or sensitive data in API responses."
    ),
    "lack_of_rate_limiting": (
        "DEFAULT_THROTTLE_CLASSES is left empty/unconfigured, or pagination is "
        "disabled, allowing unrestricted request volume or unbounded result "
        "sets that enable Denial of Service."
    ),
    "broken_function_level_authorization": (
        "DEFAULT_PERMISSION_CLASSES is left at the default AllowAny (or a view "
        "overrides permission_classes) so that non-public endpoints are "
        "reachable by users who should not have access to that function."
    ),
    "mass_assignment": (
        "A ModelForm or serializer uses Meta.exclude (denylist) or "
        "fields = \"__all__\" instead of an explicit allowlist, letting a "
        "client set fields it should not be able to control."
    ),
    "security_misconfiguration": (
        "Django settings such as DEBUG or DEBUG_PROPAGATE_EXCEPTIONS are left "
        "True in production, default passwords or hardcoded SECRET_KEY are "
        "used, or the API accepts HTTP verbs it should not support."
    ),
    "injection": (
        "User input reaches a dangerous method such as raw(), extra(), or "
        "cursor.execute() (SQL injection), or reaches yaml.load(), eval(), "
        "exec(), execfile(), or pickle-based deserialization (e.g. "
        "pandas.read_pickle()) enabling remote code execution."
    ),
    "improper_assets_management": (
        "There is no accurate inventory of API hosts/versions/environments "
        "(production, staging, test), so it is unclear which hosts, versions, "
        "or endpoints exist and who should have network access to them."
    ),
    "insufficient_logging_monitoring": (
        "Failed authentication attempts, denied access, or input validation "
        "errors are not logged with enough context, generic messages like "
        "'Error was thrown' are logged instead of stack traces, or sensitive "
        "data such as passwords, API tokens, or PII is written to logs."
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
