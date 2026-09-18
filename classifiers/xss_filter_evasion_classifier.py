"""XSS Filter Evasion Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"XSS Filter Evasion Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python xss_filter_evasion_classifier.py "some text to classify"
    python xss_filter_evasion_classifier.py --file path/to/content.txt
    echo "some text" | python xss_filter_evasion_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "XSS Filter Evasion Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "XSS_Filter_Evasion_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's catalog of filter-bypass XSS
# test vectors. Each description is written so Jev (the TypeSafe model) can
# distinguish it from neighboring categories that use similar mechanisms.
CATEGORIES = {
    "script_tag_variant_injection": (
        "Content contains or describes a <script>-tag-based XSS payload "
        "variant, including malformed or unclosed tags, doubled/split tags "
        "like <<SCRIPT>, or a protocol-relative src attribute, intended to "
        "bypass filters that look for a simple exact <script> pattern."
    ),
    "event_handler_injection": (
        "Content contains or describes injecting an HTML event-handler "
        "attribute (such as onmouseover, onerror, onload, or onblur) on a "
        "non-script tag like IMG, BODY, or A, to execute JavaScript without "
        "ever using a <script> element."
    ),
    "javascript_uri_scheme_abuse": (
        "Content contains or describes a javascript: URI placed in an "
        "href, src, or background attribute of an A, IMG, INPUT, or BODY "
        "tag, executing code when the element is rendered or interacted "
        "with."
    ),
    "character_encoding_obfuscation": (
        "Content contains or describes an XSS payload obfuscated via "
        "decimal or hexadecimal HTML character references, "
        "String.fromCharCode(), or other character-level encodings used "
        "specifically to bypass string- or keyword-matching filters."
    ),
    "whitespace_and_tag_syntax_tricks": (
        "Content contains or describes inserting tabs, newlines, null "
        "bytes, slashes, or other non-alpha-non-digit characters between "
        "tag names, attributes, or event handlers to break a filter's "
        "assumption about whitespace while the browser still parses the "
        "tag correctly."
    ),
    "polyglot_multi_context_payload": (
        "Content contains or describes a single payload deliberately "
        "engineered to execute across multiple parsing contexts at once "
        "(HTML, script string, JavaScript, URL), such as a polyglot XSS "
        "locator string that closes out of several tag/attribute contexts "
        "in sequence."
    ),
    "non_script_tag_vectors": (
        "Content contains or describes using non-<script> HTML elements or "
        "CSS as the execution vector, such as an SVG onload attribute, a "
        "STYLE list-style-image url(javascript:...), VBScript in an image "
        "src, or embedding via IFRAME/EMBED/OBJECT."
    ),
    "filter_bypass_via_alternate_rendering": (
        "Content discusses a specific browser rendering-engine quirk, such "
        "as Firefox auto-closing an unclosed tag, IE/Trident tolerating a "
        "'half-open' tag, or a rendering engine accepting characters a "
        "filter did not anticipate, exploited to defeat a filter's "
        "assumptions about well-formed markup."
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
