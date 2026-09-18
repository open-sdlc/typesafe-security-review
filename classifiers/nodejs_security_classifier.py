"""Nodejs Security Cheat Sheet classifier built on the TypeSafe System One
API.

Classifies input text against sub-categories drawn from the OWASP
"Nodejs Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python nodejs_security_classifier.py "some text to classify"
    python nodejs_security_classifier.py --file path/to/content.txt
    echo "some text" | python nodejs_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Nodejs Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Nodejs_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "Application Security", "Error
# & Exception Handling", and "Server/Platform Security" recommendations.
# Each description is written so Jev (the TypeSafe model) can distinguish it
# from neighboring categories -- be specific about what does and does not
# count.
CATEGORIES = {
    "callback_ordering_race_condition": (
        "Asynchronous code relies on incorrect ordering assumptions -- such "
        "as a synchronous call placed after an async callback that it "
        "actually depends on -- creating a race condition that can affect "
        "security-relevant logic like authentication checks."
    ),
    "missing_request_size_limits": (
        "Incoming HTTP request bodies are parsed/buffered without a size "
        "limit configured per content type, allowing an attacker to exhaust "
        "server memory or disk with oversized requests."
    ),
    "event_loop_blocking_dos": (
        "CPU-intensive, synchronous JavaScript operations block Node.js's "
        "single-threaded event loop, preventing the server from responding to "
        "other requests and enabling a denial-of-service condition."
    ),
    "insufficient_input_validation": (
        "User-supplied input is not validated or sanitized against an "
        "allowlist/expected schema, opening the door to injection attacks "
        "such as SQL injection, command injection, LDAP injection, or path "
        "traversal."
    ),
    "missing_output_escaping": (
        "HTML or JavaScript content derived from user input is rendered back "
        "to users without context-aware escaping or a maintained sanitizer, "
        "enabling cross-site scripting (XSS)."
    ),
    "insufficient_security_logging": (
        "The application does not log security-relevant activity (errors, "
        "authentication events, exceptions) in a way that supports debugging "
        "or incident response."
    ),
    "missing_brute_force_protection": (
        "Login or other sensitive endpoints lack rate limiting, delay, or "
        "lockout mechanisms, leaving them vulnerable to automated brute-force "
        "or credential-stuffing attacks."
    ),
    "vulnerable_runtime_or_config": (
        "The application runs on an outdated Node.js version, uses "
        "vulnerable third-party packages, or has an insecure server/platform "
        "configuration."
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
