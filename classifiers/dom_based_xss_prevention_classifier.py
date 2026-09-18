"""DOM based XSS Prevention Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"DOM based XSS Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python dom_based_xss_prevention_classifier.py "some text to classify"
    python dom_based_xss_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python dom_based_xss_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "DOM based XSS Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "DOM_based_XSS_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "unsafe_html_subcontext_sink": (
        "Untrusted data is written into the HTML subcontext of the execution "
        "context via dangerous methods like element.innerHTML, "
        "element.outerHTML, document.write(), or document.writeln() without "
        "both HTML-encoding and JavaScript-encoding the data first."
    ),
    "html_attribute_subcontext_encoding_mistake": (
        "Untrusted data is written into a non-executing HTML attribute "
        "within a DOM execution context using the wrong encoding, such as "
        "applying HTML-attribute-encoding (causing double-encoding/broken "
        "display) instead of the correct JavaScript-only encoding."
    ),
    "event_handler_or_js_code_subcontext_injection": (
        "Untrusted data is placed directly into an event handler attribute "
        "(e.g. via setAttribute('onclick', ...)) or into JavaScript code "
        "subcontexts like setTimeout/setInterval/new Function with a string "
        "argument, where JavaScript encoding does not prevent execution."
    ),
    "css_attribute_subcontext_injection": (
        "Untrusted data is inserted into a CSS attribute/style subcontext "
        "(e.g. via a CSS url() expression) within the execution context "
        "without JavaScript-escaping and URL-encoding it first, risking "
        "execution via javascript: URLs or CSS expression() tricks."
    ),
    "url_attribute_subcontext_injection": (
        "Untrusted data is used to build a URL assigned to an href/src "
        "attribute from JavaScript without URL-encoding then JavaScript-"
        "encoding it, potentially allowing an attacker-controlled protocol "
        "such as javascript: to execute."
    ),
    "unsafe_dom_population_instead_of_safe_sink": (
        "The code populates the DOM with untrusted data using an unsafe "
        "method rather than a safe sink such as `textContent`, missing the "
        "simplest and most robust DOM XSS fix (rule #6/#7 of this cheat "
        "sheet)."
    ),
    "setattribute_type_coercion_hazard": (
        "`element.setAttribute(name, value)` is used with an attacker-"
        "influenced attribute name so that the value string is implicitly "
        "coerced into an executing DOM attribute type (like an event "
        "handler), even though the value itself was properly encoded."
    ),
    "reflected_vs_dom_source_confusion": (
        "The described vulnerability is a server-side reflected/stored "
        "injection (fixed by server-side output encoding) rather than a true "
        "client-side DOM XSS issue where untrusted data flows from a "
        "browser-side source (URL, DOM) into a sink purely in client code."
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
