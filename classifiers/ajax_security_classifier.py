"""AJAX Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"AJAX Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python ajax_security_classifier.py "some text to classify"
    python ajax_security_classifier.py --file path/to/content.txt
    echo "some text" | python ajax_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "AJAX Security Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/AJAX_Security_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "dom_xss_innerhtml": (
        "Untrusted data from an AJAX response, user input, or another external "
        "source is assigned to innerHTML (or a framework equivalent like "
        "dangerouslySetInnerHTML) without sanitization, allowing injected "
        "HTML/JavaScript to execute in the browser (DOM-based XSS)."
    ),
    "dynamic_code_evaluation": (
        "Untrusted or dynamic data is passed to eval(), new Function(), or "
        "another code-evaluation construct, enabling arbitrary script execution."
    ),
    "client_side_security_reliance": (
        "A security decision, business rule, encryption operation, or other "
        "security-impacting logic is performed only in client-side JavaScript, "
        "where a user can bypass it via browser tools or dev consoles instead of "
        "the server enforcing it."
    ),
    "unencoded_output_context": (
        "Data is embedded into an HTML, JavaScript, CSS, XML, or JSON output "
        "context without proper context-aware encoding, risking injection that "
        "changes the data's logical meaning."
    ),
    "direct_backend_service_access": (
        "A backend AJAX/REST service assumes it will only ever be called by the "
        "application's own client-side script and skips independent input "
        "validation, even though an attacker can call the service endpoint "
        "directly."
    ),
    "json_array_hijacking": (
        "A JSON response returns a bare array as its outermost structure instead "
        "of wrapping the array inside a top-level object, making it susceptible "
        "to JSON hijacking in older browsers via array constructor overriding."
    ),
    "client_secret_transmission": (
        "Secrets, internal configuration, or server-only sensitive logic are "
        "transmitted to or embedded in client-side code, where any user can read "
        "or modify them."
    ),
    "unsafe_manual_serialization": (
        "XML or JSON payloads are constructed or parsed by hand-written "
        "serialization code instead of a reviewed library/framework, risking "
        "injection bugs or reference/value type mistakes."
    ),
    "missing_csrf_protection_ajax": (
        "A state-changing AJAX request lacks CSRF protections (tokens, SameSite "
        "cookies, or equivalent), allowing a forged cross-site request to be "
        "executed with the victim's session."
    ),
    "untrusted_input_source_assumption": (
        "Data from a source often assumed to be safe -- browser "
        "localStorage/sessionStorage, hidden form fields, cached responses, or "
        "third-party/internal service responses -- is treated as trusted instead "
        "of being validated like any other untrusted input."
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
