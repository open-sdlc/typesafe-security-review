"""DOM Clobbering Prevention Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"DOM Clobbering Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python dom_clobbering_prevention_classifier.py "some text to classify"
    python dom_clobbering_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python dom_clobbering_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "DOM Clobbering Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "DOM_Clobbering_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "id_name_attribute_namespace_collision": (
        "Injected HTML elements use an id or name attribute that matches the "
        "name of a security-sensitive JavaScript variable or a window/document "
        "property, overshadowing its expected value via named property "
        "access (DOM Clobbering's core mechanism)."
    ),
    "clobbering_via_non_script_html_injection": (
        "An attacker who cannot inject <script> tags (due to sanitization or "
        "a script-blocking CSP) instead injects plain, non-script HTML markup "
        "(such as <a id=...> or <form name=...>) intended to manipulate "
        "application logic through DOM Clobbering."
    ),
    "missing_html_sanitizer_named_property_protection": (
        "An HTML sanitizer is used without enabling protections against named "
        "property collisions, e.g. DOMPurify without SANITIZE_NAMED_PROPS, or "
        "the browser Sanitizer API without blocking id/name attributes."
    ),
    "sensitive_object_not_frozen": (
        "A sensitive DOM object or its properties are not frozen with "
        "Object.freeze() or similar, leaving them overwritable by a clobbered "
        "named HTML element."
    ),
    "implicit_or_global_variable_declaration": (
        "A variable used for a security-sensitive purpose (like a redirect "
        "URL or script src) is declared implicitly, attached to `window`/"
        "`document`, or otherwise placed in global scope rather than using an "
        "explicit local `let`/`const` declaration."
    ),
    "missing_type_checking_before_use": (
        "A window/document property is used for a sensitive operation (URL "
        "construction, redirect, script loading) without first verifying its "
        "type (e.g. via `instanceof`), so a clobbered Element reference could "
        "be silently substituted for the expected string/object."
    ),
    "trusting_builtin_document_properties_unvalidated": (
        "Code trusts a built-in document/window API property's value for a "
        "sensitive operation without validation, even though named HTML "
        "elements can override built-in properties via the named property "
        "visibility algorithm."
    ),
    "missing_csp_script_src_restriction": (
        "The page does not restrict script sources via a Content-Security-"
        "Policy script-src directive, widening the impact of a DOM Clobbering "
        "attack that attempts to load an attacker-controlled script."
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
