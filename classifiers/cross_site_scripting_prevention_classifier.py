"""Cross Site Scripting Prevention Cheat Sheet classifier built on the
TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Cross Site Scripting Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python cross_site_scripting_prevention_classifier.py "some text to classify"
    python cross_site_scripting_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python cross_site_scripting_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Cross Site Scripting Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_context_aware_output_encoding": (
        "Untrusted data is inserted into an HTML body, attribute, "
        "JavaScript, CSS, or URL context without the context-specific "
        "encoding (HTML entity, HTML attribute, JS, CSS hex, or URL "
        "encoding) that context requires, permitting script injection."
    ),
    "framework_escape_hatch_misuse": (
        "A modern framework's raw-HTML/DOM escape hatch is used with "
        "untrusted data, such as React's dangerouslySetInnerHTML, Angular's "
        "bypassSecurityTrustAs*, Lit's unsafeHTML, or Vue's v-html, without "
        "sanitizing the content first."
    ),
    "unsafe_url_protocol_handling": (
        "A framework or component fails to validate that a user-controlled "
        "URL (e.g. an href or src) uses an allow-listed http/https scheme, "
        "leaving it able to accept a javascript: or data: URL that executes "
        "code."
    ),
    "missing_html_sanitization_for_rich_content": (
        "User-authored rich HTML (e.g. from a WYSIWYG editor) is rendered "
        "without passing it through a robust HTML sanitizer such as "
        "DOMPurify, or a previously sanitized string is mutated/modified "
        "afterward, reintroducing risk."
    ),
    "dangerous_sink_usage": (
        "Untrusted data reaches a dangerous JavaScript sink such as "
        "innerHTML/outerHTML, eval(), setTimeout/setInterval with a string "
        "argument, or an inline event handler attribute, instead of a safe "
        "sink like textContent or setAttribute."
    ),
    "csp_used_as_sole_xss_defense": (
        "Content Security Policy is relied upon as the only or primary "
        "defense against XSS, rather than as a defense-in-depth layer on top "
        "of proper output encoding and sanitization."
    ),
    "insecure_json_response_content_type": (
        "A JSON API response is served with a Content-Type of text/html (or "
        "no explicit JSON content type) instead of application/json, risking "
        "the response being interpreted and executed as HTML/script by the "
        "browser."
    ),
    "missing_trusted_types_enforcement": (
        "The application does not enable Trusted Types "
        "(require-trusted-types-for 'script') on Chromium-based browsers to "
        "force DOM XSS sink assignments through a vetted policy, leaving "
        "entire classes of DOM XSS unmitigated."
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
