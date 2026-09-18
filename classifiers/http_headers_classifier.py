"""HTTP Headers Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"HTTP Headers Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python http_headers_classifier.py "some text to classify"
    python http_headers_classifier.py --file path/to/content.txt
    echo "some text" | python http_headers_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "HTTP Headers Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "HTTP_Headers_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's per-header sections: framing/
# MIME/CSP/HSTS protections, cookie attributes, CORS, cross-origin isolation
# headers, server fingerprinting, referrer policy, and caching.
CATEGORIES = {
    "missing_clickjacking_protection": (
        "A response can be rendered inside a <frame>/<iframe> because it is "
        "missing X-Frame-Options (or a CSP frame-ancestors directive), "
        "enabling clickjacking attacks."
    ),
    "missing_mime_sniffing_protection": (
        "A response omits X-Content-Type-Options: nosniff, letting a "
        "browser MIME-sniff the content and interpret a non-executable "
        "resource as executable (MIME confusion attack)."
    ),
    "missing_or_weak_content_security_policy": (
        "A page that renders scripts is missing a Content-Security-Policy "
        "header, or the CSP is misconfigured (e.g. allows 'unsafe-inline' or "
        "wildcard sources), weakening XSS/data-injection mitigation."
    ),
    "missing_hsts_enforcement": (
        "A site served over HTTPS omits the Strict-Transport-Security "
        "header (or sets too short a max-age), allowing a downgrade to plain "
        "HTTP or exposing users to SSL-stripping attacks."
    ),
    "insecure_cookie_attributes": (
        "A Set-Cookie header is missing the Secure, HttpOnly, or SameSite "
        "attribute, letting the cookie be sent over plain HTTP, be read by "
        "JavaScript, or be attached to cross-site requests."
    ),
    "overly_permissive_cors_headers": (
        "Access-Control-Allow-Origin is set to '*' or blindly reflects the "
        "Origin header instead of an explicit allow-list of trusted "
        "origins, especially on responses containing sensitive data."
    ),
    "missing_advanced_isolation_headers": (
        "A page is missing Cross-Origin-Opener-Policy, Cross-Origin-"
        "Embedder-Policy, Cross-Origin-Resource-Policy, or Permissions-"
        "Policy, leaving it exposed to cross-origin attacks like Spectre or "
        "unauthorized use of browser features (camera, microphone, "
        "geolocation)."
    ),
    "server_technology_fingerprinting": (
        "A response includes Server, X-Powered-By, X-AspNet-Version, or "
        "X-AspNetMvc-Version headers that disclose the server software or "
        "framework/version in use."
    ),
    "missing_referrer_policy": (
        "A response does not send a Referrer-Policy header (or sends a "
        "permissive one), leaking full referrer URLs including sensitive "
        "query strings to third-party sites."
    ),
    "unsafe_caching_of_sensitive_data": (
        "A response containing sensitive data relies on default caching "
        "behavior or a permissive Cache-Control value instead of `no-store`, "
        "risking sensitive data being stored in a shared or browser cache."
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
