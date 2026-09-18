"""XML Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"XML Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python xml_security_classifier.py "some text to classify"
    python xml_security_classifier.py --file path/to/content.txt
    echo "some text" | python xml_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "XML Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "XML_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's two attack surfaces --
# malformed XML documents and invalid/insufficiently-restricted XML
# documents. Each description is written so Jev (the TypeSafe model) can
# distinguish it from neighboring categories.
CATEGORIES = {
    "malformed_document_handling": (
        "Content discusses how an XML parser reacts to a malformed (not "
        "well-formed) XML document, including asymmetric CPU/time "
        "consumption when processing malformed input compared to "
        "well-formed input."
    ),
    "coercive_parsing_dos": (
        "Content describes feeding a parser deeply nested XML elements "
        "without their corresponding closing tags, or a similarly "
        "structured input, intended to exhaust parser memory or stack and "
        "cause a denial of service."
    ),
    "schema_validation_gaps": (
        "Content discusses XML documents being processed without any XML "
        "Schema at all, or with a schema so unrestrictive (such as a bare "
        "DTD) that it fails to constrain element structure, ordering, or "
        "count."
    ),
    "numeric_data_type_abuse": (
        "Content discusses exploiting loosely typed numeric XML schema "
        "fields: missing positive/negative restrictions allowing a "
        "negative quantity or price, a zero value used as a division "
        "denominator, or unexpected Infinity/NaN values in float or double "
        "fields."
    ),
    "unrestricted_string_or_pattern_fields": (
        "Content discusses XML schema string fields that lack enumeration, "
        "minLength/maxLength, or pattern restrictions, allowing "
        "unexpectedly long, malformed, or out-of-range values to be "
        "accepted as valid."
    ),
    "jumbo_payload_dos": (
        "Content describes sending an abnormally large or deeply repeated "
        "set of XML elements or attributes (a depth or width attack), "
        "including small payloads that expand into huge documents via "
        "entity references, to exhaust server resources cheaply."
    ),
    "schema_poisoning": (
        "Content describes an attacker modifying or substituting a local "
        "or remote XML schema or DTD, for example via weak file "
        "permissions or intercepted/redirected network traffic, to alter "
        "validation rules or enable external entity processing."
    ),
    "element_injection_via_structure": (
        "Content describes an attacker injecting additional well-formed "
        "opening and closing XML tags to manipulate application logic that "
        "reads only the first occurrence of a repeated element, exploiting "
        "the absence of a schema that would otherwise enforce structure."
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
