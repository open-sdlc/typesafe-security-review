"""REST Assessment Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"REST Assessment Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python rest_assessment_classifier.py "some text to classify"
    python rest_assessment_classifier.py --file path/to/content.txt
    echo "some text" | python rest_assessment_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "REST Assessment Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "hidden_attack_surface": (
        "The RESTful service exposes functions or parameters that are never used "
        "by the inspected client application and so are invisible to normal UI "
        "inspection, requiring traffic capture or documentation to discover."
    ),
    "nonstandard_parameter_location": (
        "A parameter is passed somewhere other than a standard query string -- "
        "inside an HTTP header, a URL path segment, or a structured JSON/XML body "
        "-- making it harder to identify as a parameter worth testing."
    ),
    "custom_auth_reverse_engineering": (
        "The service uses a custom authentication or session mechanism (e.g. a "
        "bespoke security token) that popular scanning/proxy tools cannot "
        "natively track, requiring manual reverse engineering to emulate a login "
        "sequence."
    ),
    "url_segment_parameter_pattern": (
        "A URL path segment repeats across many requests with varying values that "
        "look like an ID, date, or token (e.g. '/svc/2013-10-21/use.php'), "
        "indicating it is actually an embedded parameter rather than a static "
        "path."
    ),
    "structured_body_fuzzing_scale": (
        "A JSON or XML request body contains dozens of nested fields, each a "
        "potential fuzz target, making systematic input fuzzing of the full "
        "parameter surface impractically slow without prioritization."
    ),
    "path_vs_parameter_ambiguity": (
        "It is unclear whether a URL segment is a literal path element (returns "
        "404 on an invalid value) or a parameter (returns an application-level "
        "error), requiring probing with invalid values to disambiguate."
    ),
    "boundary_value_fuzzing_strategy": (
        "Observed valid parameter values (e.g. always-positive integers, fixed "
        "value sets) are used to derive marginal/invalid boundary values for "
        "targeted fuzzing rather than blind brute forcing."
    ),
    "missing_formal_service_description": (
        "The REST service lacks a formal machine-readable description (WSDL/WADL) "
        "or developer documentation, forcing attack-surface discovery purely from "
        "captured traffic and reverse engineering."
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
