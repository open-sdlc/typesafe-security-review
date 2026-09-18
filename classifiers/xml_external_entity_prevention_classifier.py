"""XML External Entity Prevention Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"XML External Entity Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python xml_external_entity_prevention_classifier.py "some text to classify"
    python xml_external_entity_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python xml_external_entity_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "XML External Entity Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "XML_External_Entity_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's general guidance, the XML
# parser security features matrix, and the per-language hardening recipes.
# Each description is written so Jev (the TypeSafe model) can distinguish it
# from neighboring categories.
CATEGORIES = {
    "external_entity_resolution": (
        "Content describes an XML parser resolving an external entity "
        "declaration (e.g. <!ENTITY xxe SYSTEM \"file:///etc/passwd\">), "
        "allowing file disclosure, SSRF, or internal network/port "
        "scanning."
    ),
    "doctype_declaration_not_disabled": (
        "Content discusses failing to disable DOCTYPE declarations or DTD "
        "processing entirely in an XML parser, described as the single "
        "safest general prevention against XXE."
    ),
    "billion_laughs_entity_expansion": (
        "Content describes nested or recursive internal entity definitions "
        "(a 'Billion Laughs' style attack) causing exponential memory or "
        "CPU consumption and denial of service during XML parsing."
    ),
    "external_dtd_or_schema_fetching": (
        "Content discusses a parser loading a remote or external DTD or "
        "schema definition referenced by an XML document, enabling blind "
        "XXE or unwanted outbound network requests triggered during "
        "parsing or validation."
    ),
    "xinclude_processing": (
        "Content discusses XInclude processing being enabled in an XML "
        "parser, allowing inclusion of external files and resulting in "
        "local file disclosure or SSRF via the file:// or http:// scheme."
    ),
    "parser_specific_hardening_config": (
        "Content discusses concrete parser or library configuration "
        "settings used to prevent XXE, such as disallow-doctype-decl, "
        "setFeature calls, FEATURE_SECURE_PROCESSING, or custom entity "
        "resolvers, across languages like Java, .NET, Python, PHP, or "
        "C/C++ XML libraries."
    ),
    "ssrf_via_xml_parsing": (
        "Content describes using XML parsing of untrusted input to make "
        "the server issue outbound requests to an attacker-chosen internal "
        "or external address, i.e. Server-Side Request Forgery driven by an "
        "XML payload."
    ),
    "legacy_or_default_parser_config": (
        "Content discusses relying on a default, legacy, or classpath-"
        "selected XML parser implementation that silently permits external "
        "entity resolution because secure processing settings were never "
        "explicitly applied by the developer."
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
