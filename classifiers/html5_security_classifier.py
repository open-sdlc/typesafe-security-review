"""HTML5 Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"HTML5 Security Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python html5_security_classifier.py "some text to classify"
    python html5_security_classifier.py --file path/to/content.txt
    echo "some text" | python html5_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "HTML5 Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "HTML5_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's Communication APIs (Web
# Messaging, CORS, WebSockets/SSE), Storage APIs, Tabnabbing, Sandboxed
# frames, PII input hints, and Offline Applications/Service Worker sections.
CATEGORIES = {
    "unsafe_postmessage_origin_handling": (
        "postMessage() is called with a wildcard '*' target origin instead "
        "of an explicit expected origin, or the receiving page fails to "
        "check the sender's origin and validate the data attribute of the "
        "message event."
    ),
    "dom_based_xss_via_data_evaluation": (
        "Data received via postMessage, a Web Worker, or Server-Sent Events "
        "is evaluated as code (e.g. via eval()) or inserted into the DOM "
        "with innerHTML instead of textContent, creating a DOM-based XSS "
        "risk."
    ),
    "overly_permissive_cors_configuration": (
        "Access-Control-Allow-Origin is set to '*' or blindly reflects the "
        "Origin header on a URL with sensitive content, or an XHR/CORS check "
        "relies solely on the Origin header for access control."
    ),
    "sensitive_data_in_client_storage": (
        "Session identifiers, credentials, or other sensitive/PII data are "
        "stored in localStorage, sessionStorage, or IndexedDB, where a "
        "single XSS flaw could read or tamper with them."
    ),
    "tabnabbing_via_unprotected_links": (
        "An HTML link or window.open() call with a target/new window omits "
        "rel=\"noopener noreferrer\" (or the noopener,noreferrer "
        "windowFeatures), allowing reverse tabnabbing of the parent page."
    ),
    "missing_iframe_sandboxing_or_frame_protection": (
        "Untrusted content is embedded in an iframe without the sandbox "
        "attribute, or the page does not send X-Frame-Options / CSP "
        "frame-ancestors to prevent clickjacking."
    ),
    "insecure_service_worker_registration": (
        "A Service Worker script is registered from a non-HTTPS origin, from "
        "an untrusted/cross-origin source, or with an overly broad scope, "
        "risking interception of requests across the site."
    ),
    "pii_or_credential_autocomplete_exposure": (
        "A form field for PII (name, email, phone) or login credentials "
        "(username, password) omits autocomplete=\"off\"/spellcheck=\"false\", "
        "letting the browser cache sensitive values."
    ),
    "unvalidated_websocket_or_sse_origin": (
        "A WebSocket or EventSource (Server-Sent Events) endpoint's URL or "
        "the origin of incoming messages is not validated against an "
        "allow-list of trusted domains."
    ),
    "web_worker_abuse": (
        "A Web Worker script is created from user-supplied input, or a "
        "malicious/uncontrolled worker consumes excessive CPU, risking "
        "Denial of Service or further CORS-based exploitation."
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
