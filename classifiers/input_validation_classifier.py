"""Input Validation Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Input Validation Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python input_validation_classifier.py "some text to classify"
    python input_validation_classifier.py --file path/to/content.txt
    echo "some text" | python input_validation_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Input Validation Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Input_Validation_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "denylist_reliance": (
        "Input is validated primarily using a denylist/blocklist of known-bad "
        "characters or patterns (e.g. blocking the apostrophe, the string "
        "'1=1', or '<script>') instead of allow-list validation, which is "
        "trivial for an attacker to bypass."
    ),
    "client_side_only_validation": (
        "Input validation is implemented only via client-side JavaScript with "
        "no equivalent enforcement on the server, allowing an attacker to "
        "bypass it by disabling JavaScript or replaying requests through a "
        "proxy."
    ),
    "free_form_unicode_text_validation": (
        "Free-form Unicode text is validated using normalization to a "
        "canonical encoding plus Unicode character-category or individual-"
        "character allowlisting, rather than blocking punctuation/characters "
        "outright."
    ),
    "regex_redos_risk": (
        "A regular expression used for input validation is vulnerable to "
        "catastrophic backtracking / ReDoS (Regular Expression Denial of "
        "Service) due to unbounded wildcards or nested repeating groups."
    ),
    "structured_field_syntactic_validation": (
        "Correct syntax of a structured field (e.g. ZIP code, date, currency, "
        "a drop-down/radio-button value) is enforced via an allow-list "
        "regular expression or exact matching against the discrete set of "
        "valid options."
    ),
    "semantic_business_validation": (
        "A value's correctness is enforced in its specific business context "
        "beyond mere syntax, such as verifying a start date precedes an end "
        "date or that a price falls within an expected range."
    ),
    "file_upload_type_and_size_validation": (
        "An uploaded file's extension/content-type and size are validated, "
        "and the file is safely renamed/stored server-side rather than using "
        "user-controlled filenames or paths."
    ),
    "dangerous_upload_file_types": (
        "An upload feature allows inherently dangerous file types such as "
        "crossdomain.xml, clientaccesspolicy.xml, .htaccess/.htpasswd, or "
        "web-executable scripts (aspx, asp, jsp, php, cgi, js) instead of "
        "restricting to a safe allow-list of extensions."
    ),
    "email_address_validation": (
        "A user-submitted email address is checked either syntactically "
        "(format/character checks per RFC 5321) or semantically (confirming "
        "ownership by sending a verification email/code)."
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
