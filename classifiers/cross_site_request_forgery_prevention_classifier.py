"""Cross-Site Request Forgery Prevention Cheat Sheet classifier built on the
TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Cross-Site Request Forgery Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python cross_site_request_forgery_prevention_classifier.py "some text to classify"
    python cross_site_request_forgery_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python cross_site_request_forgery_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Cross-Site Request Forgery Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_or_unvalidated_csrf_token": (
        "A state-changing request (e.g. transferring funds, changing a "
        "password) is accepted by the server without requiring and validating "
        "a unique, unpredictable, per-session or per-request CSRF token, "
        "allowing a forged cross-site request to succeed using only the "
        "victim's ambient cookies."
    ),
    "csrf_token_transmitted_or_leaked_insecurely": (
        "A CSRF token is placed in a GET request URL, or otherwise leaks via "
        "browser history, server logs, or the Referer header, rather than "
        "being sent as a hidden form field or custom header."
    ),
    "naive_double_submit_cookie_weakness": (
        "The application relies on the 'naive' Double-Submit Cookie pattern "
        "(comparing a cookie value to a request value with no session "
        "binding or HMAC signing), which is bypassable by an attacker who can "
        "write cookies on the target domain, e.g. via a vulnerable "
        "subdomain."
    ),
    "csrf_token_not_bound_to_session": (
        "A CSRF token is not cryptographically bound (e.g. via HMAC) to the "
        "user's authenticated session identifier, weakening protection since "
        "the token's authenticity and session linkage cannot be verified."
    ),
    "missing_samesite_cookie_attribute": (
        "Session or authentication cookies are missing a SameSite=strict or "
        "SameSite=lax attribute, allowing them to be included in cross-site "
        "requests that a stricter cookie policy would have blocked."
    ),
    "missing_fetch_metadata_or_origin_verification": (
        "The server does not check Sec-Fetch-Site or standard Origin/Referer "
        "headers to reject obviously cross-site requests, missing a "
        "lightweight defense layer against CSRF (with no fallback for legacy "
        "browsers that lack Sec-Fetch-* support)."
    ),
    "csrf_token_reused_indefinitely": (
        "A single CSRF token is reused across the entire user session or "
        "indefinitely rather than being appropriately scoped, expanding the "
        "window during which a leaked token remains exploitable."
    ),
    "xss_undermining_csrf_defenses": (
        "A Cross-Site Scripting (XSS) vulnerability is present or implied, "
        "which would allow an attacker to read and exfiltrate CSRF tokens "
        "directly from the page, defeating all token-based CSRF mitigations."
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
