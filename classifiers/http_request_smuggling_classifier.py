"""HTTP Request Smuggling classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the CWE (Common
Weakness Enumeration) entry for Inconsistent Interpretation of HTTP Requests
(HTTP Request/Response Smuggling):
https://cwe.mitre.org/data/definitions/444.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python http_request_smuggling_classifier.py "some text to classify"
    python http_request_smuggling_classifier.py --file path/to/content.txt
    echo "some text" | python http_request_smuggling_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Inconsistent Interpretation of HTTP Requests (CWE-444)"
CHEATSHEET_URL = "https://cwe.mitre.org/data/definitions/444.html"

# Sub-categories drawn from CWE-444 (Inconsistent Interpretation of HTTP
# Requests, i.e. HTTP Request/Response Smuggling): exploiting discrepancies
# between how a front-end (proxy/load balancer/CDN) and back-end server parse
# the boundaries of an HTTP request, letting an attacker "smuggle" a hidden
# second request. Each description is written so Jev (the TypeSafe model) can
# distinguish it from neighboring categories -- this is distinct from
# http_headers_classifier.py (response security headers) and from
# cross_site_request_forgery_prevention_classifier.py /
# server_side_request_forgery_prevention_classifier.py.
CATEGORIES = {
    "conflicting_content_length_and_transfer_encoding": (
        "A single HTTP request contains both a Content-Length header and a "
        "Transfer-Encoding: chunked header with conflicting framing "
        "information, allowing a front-end and back-end server to disagree "
        "about where the request body ends (a CL.TE desynchronization "
        "attack)."
    ),
    "duplicate_content_length_or_transfer_encoding_headers": (
        "An HTTP request contains multiple Content-Length headers with "
        "different values, or multiple Transfer-Encoding headers, causing "
        "different HTTP implementations to pick different header instances "
        "and disagree on request boundaries (a TE.TE or CL.CL "
        "desynchronization attack)."
    ),
    "ambiguous_chunked_encoding_parsing": (
        "A chunked-transfer-encoded request body contains malformed, "
        "ambiguous, or non-standard chunk-size lines (e.g. extra whitespace, "
        "chunk extensions, non-hex characters, or an unexpected "
        "terminating sequence) that different parsers may interpret "
        "differently."
    ),
    "obfuscated_or_malformed_request_line_or_headers": (
        "An HTTP request line or header name is obfuscated with unusual "
        "casing, extra whitespace, tab characters, or other malformed "
        "syntax specifically crafted so that one HTTP parser accepts or "
        "ignores it while another parser interprets it differently, letting "
        "the request slip past a front-end's inspection."
    ),
    "front_end_back_end_parser_discrepancy": (
        "A reverse proxy, load balancer, or CDN in front of an origin/"
        "back-end server uses a different HTTP parsing library, version, or "
        "leniency configuration than the back-end, creating a structural "
        "opportunity for request smuggling even without a specific "
        "malformed payload being described yet."
    ),
    "request_pipelining_response_queue_desync": (
        "HTTP request pipelining (sending multiple requests over a single "
        "persistent connection without waiting for each response) results in "
        "responses being matched to the wrong request, desynchronizing the "
        "response queue between client and server or between two hops of a "
        "proxy chain."
    ),
    "crlf_header_injection_splitting_request": (
        "Untrusted input is placed into an HTTP header or request line "
        "without neutralizing embedded carriage-return/line-feed (CR/LF) or "
        "other control characters, allowing the input to terminate the "
        "current header/request and inject a second, attacker-controlled "
        "request or header."
    ),
    "http2_downgrade_smuggling": (
        "A gateway or proxy that translates HTTP/2 requests from clients "
        "into HTTP/1.1 requests toward the back-end introduces a request "
        "smuggling opportunity because the downgrade process can misrepresent "
        "framing information (such as pseudo-headers or content-length) that "
        "existed safely under HTTP/2's binary framing."
    ),
    "request_smuggling_used_to_bypass_front_end_access_control": (
        "A smuggled/desynchronized request is used to bypass access "
        "controls, authentication, or routing rules enforced only at the "
        "front-end proxy layer, reaching the back-end as if it originated "
        "from a different, more trusted request."
    ),
    "response_splitting_or_cache_poisoning_via_smuggling": (
        "A smuggled request or injected response is used to poison a shared "
        "cache, hijack another user's response on a pipelined/multiplexed "
        "connection, or perform HTTP response splitting against downstream "
        "clients or intermediaries."
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
