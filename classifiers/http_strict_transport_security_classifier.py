"""HTTP Strict Transport Security Cheat Sheet classifier built on the
TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"HTTP Strict Transport Security Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python http_strict_transport_security_classifier.py "some text to classify"
    python http_strict_transport_security_classifier.py --file path/to/content.txt
    echo "some text" | python http_strict_transport_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "HTTP Strict Transport Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "HTTP_Strict_Transport_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's Threats, Examples, Problems, and
# Browser Support sections covering HSTS header configuration and pitfalls.
CATEGORIES = {
    "missing_hsts_header": (
        "A site served over HTTPS does not send the Strict-Transport-"
        "Security response header at all, leaving users able to connect over "
        "plain HTTP and be subject to man-in-the-middle interception."
    ),
    "insufficient_max_age": (
        "The Strict-Transport-Security header's max-age directive is set too "
        "short (or to 0), reducing the window during which browsers enforce "
        "HTTPS-only access for the domain."
    ),
    "missing_include_subdomains": (
        "The HSTS header omits includeSubDomains, leaving subdomains able to "
        "be served over plain HTTP and vulnerable to cookie manipulation or "
        "other subdomain-based attacks."
    ),
    "unsafe_preload_submission": (
        "The `preload` directive is added to the HSTS header (and/or "
        "submitted to the HSTS preload list) without understanding that this "
        "has permanent, hard-to-reverse consequences for the domain and all "
        "its subdomains."
    ),
    "ssl_stripping_mitm_exposure": (
        "A user bookmarks or manually types an http:// URL for a site "
        "without HSTS, exposing the initial request to interception or "
        "downgrade by a man-in-the-middle attacker."
    ),
    "certificate_error_override_risk": (
        "The browser allows a user to click through an invalid TLS "
        "certificate warning for the domain, which HSTS is meant to "
        "prevent by disallowing such overrides."
    ),
    "hsts_based_user_tracking": (
        "HSTS state (e.g. distinctive max-age/subdomain patterns) is used as "
        "a supercookie-like mechanism to track or fingerprint a user without "
        "relying on cookies."
    ),
    "insecure_cookies_without_secure_flag": (
        "Cookies are not marked with the Secure flag even though HSTS is in "
        "use, missing the combined protection that HSTS plus secure cookies "
        "would provide against cookie theft."
    ),
    "incomplete_https_rollout": (
        "The site serves some content over HTTP and some over HTTPS (mixed "
        "content) due to an incomplete or partial HSTS/HTTPS rollout across "
        "the domain and its subdomains."
    ),
    "browser_hsts_support_gaps": (
        "The application relies on HSTS for security without accounting for "
        "clients/browsers that do not support it (e.g. Opera Mini), leaving "
        "those users without the intended protection."
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
