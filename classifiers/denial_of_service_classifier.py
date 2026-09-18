"""Denial of Service Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Denial of Service Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python denial_of_service_classifier.py "some text to classify"
    python denial_of_service_classifier.py --file path/to/content.txt
    echo "some text" | python denial_of_service_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Denial of Service Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "application_layer_resource_exhaustion": (
        "An attack targets OSI layer 7, making the application unavailable "
        "by exhausting CPU, memory, or other server-side resources through "
        "functional abuse rather than saturating network bandwidth."
    ),
    "slow_http_attack": (
        "HTTP requests are deliberately sent very slowly or in fragments (a "
        "Slow HTTP / Slowloris-style attack), holding server connections open "
        "and stalled until the concurrent connection pool is exhausted."
    ),
    "session_or_state_resource_exhaustion": (
        "Excessive or unbounded server-side session data, or a lack of "
        "session inactivity/absolute timeouts, allows an attacker to exhaust "
        "server memory or state storage tied to user sessions."
    ),
    "input_driven_resource_allocation_abuse": (
        "User-supplied input controls the amount of memory, CPU, threads, or "
        "file storage allocated by the server (e.g. large file uploads, "
        "oversized request bodies, or input-driven loop/recursion counts), "
        "enabling a resource-exhaustion DoS."
    ),
    "network_volumetric_attack": (
        "An attack focuses on saturating network bandwidth through high "
        "traffic volume, such as amplification attacks (NTP/DNS "
        "amplification) or UDP/TCP flooding, rather than targeting the "
        "application logic."
    ),
    "data_link_layer_attack": (
        "A lower-layer network attack such as MAC flooding (overflowing a "
        "switch's MAC address table) or ARP poisoning/spoofing is used to "
        "disrupt or intercept local network communications."
    ),
    "missing_rate_limiting_or_ingress_controls": (
        "The system lacks rate limiting controls such as a minimum/maximum "
        "ingress data rate, connection timeout, total bandwidth cap, or a "
        "load limit on concurrent users per resource."
    ),
    "single_point_of_failure_or_missing_redundancy": (
        "The architecture has a single point of failure (SPOF) -- a "
        "non-redundant, stateful component with no bulkheading -- that a DoS "
        "attack could overwhelm to bring down the whole system."
    ),
    "missing_graceful_degradation_or_fault_tolerance": (
        "The application terminates abruptly or fails completely under load "
        "instead of degrading gracefully to reduced functionality, or fails "
        "to handle exceptions/overflow-underflow conditions safely during "
        "resource exhaustion."
    ),
    "missing_captcha_or_functional_abuse_puzzle": (
        "A resource-intensive or abusable function (such as an email-sending "
        "form) lacks a CAPTCHA or similar puzzle to prevent it from being "
        "triggered repeatedly by an automated attacker or bot."
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
