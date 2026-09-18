"""Server Side Request Forgery Prevention Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Server Side Request Forgery Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python server_side_request_forgery_prevention_classifier.py "some text to classify"
    python server_side_request_forgery_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python server_side_request_forgery_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Server Side Request Forgery Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "full_url_user_input": (
        "The application accepts a complete, attacker-influenced URL (rather than just an "
        "IP address or domain name) as input for a server-side request, such as an image "
        "fetch URL, webhook target, or callback URL, making the URL parser itself an attack "
        "surface."
    ),
    "ip_address_validation_bypass": (
        "An IP address value is supplied in an alternate encoding (hexadecimal, octal, "
        "dword/decimal, mixed, or URL-encoded form) intended to bypass naive string-based "
        "IP allowlist or blocklist validation logic."
    ),
    "domain_name_dns_pinning": (
        "A domain name is allowlisted but later re-resolves (via DNS rebinding or 'DNS "
        "pinning') to a different, internal IP address after validation, exploiting a "
        "time-of-check-to-time-of-use gap between the validation and the actual request."
    ),
    "internal_metadata_targeting": (
        "The request or payload targets internal/private network ranges, localhost, or a "
        "cloud instance metadata endpoint (e.g. 169.254.169.254) to reach services not "
        "meant to be externally reachable."
    ),
    "non_http_scheme_abuse": (
        "The URL or request uses a non-HTTP scheme such as file://, phar://, gopher://, "
        "dict://, ftp://, or data:// to interact with the local filesystem or another "
        "internal protocol/service instead of a normal web request."
    ),
    "unsafe_redirect_following": (
        "The server-side HTTP client follows redirects returned by the target server, "
        "allowing an attacker to point an allowlisted destination to redirect the request "
        "toward a disallowed internal target, bypassing input validation."
    ),
    "webhook_callback_url_abuse": (
        "A user-supplied webhook handler or callback URL feature (e.g. avatar image URL, "
        "custom webhook) is used to make the application issue requests to attacker-chosen "
        "destinations."
    ),
    "network_layer_segmentation_gap": (
        "Defense-in-depth network controls are missing or insufficient, such as absent "
        "firewall rules or network segmentation that would otherwise restrict a compromised "
        "application server from reaching internal-only systems."
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
