"""REST Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"REST Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python rest_security_classifier.py "some text to classify"
    python rest_security_classifier.py --file path/to/content.txt
    echo "some text" | python rest_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "REST Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_transport_encryption": (
        "A REST endpoint accepts or is described as accepting plain HTTP rather "
        "than requiring HTTPS/TLS, exposing credentials, API keys, or JWTs in "
        "transit to eavesdropping or tampering."
    ),
    "decentralized_missing_access_control": (
        "A non-public REST endpoint performs no local access-control check of its "
        "own, or user authentication is not centralized behind an Identity "
        "Provider issuing access tokens."
    ),
    "jwt_validation_weakness": (
        "A JWT is accepted with 'alg: none', without verifying its signature/MAC, "
        "or without checking standard claims such as iss, aud, exp, or nbf, or "
        "there is no denylist mechanism for early session termination via jti."
    ),
    "unrestricted_api_key_usage": (
        "A public REST endpoint lacks API-key based rate limiting or 429 "
        "responses for abusive traffic, or relies on API keys alone to protect "
        "sensitive or high-value resources."
    ),
    "http_method_tampering": (
        "The service does not restrict incoming requests to an allowlist of HTTP "
        "methods per resource, or an attacker uses HTTP verb tampering to bypass "
        "authentication/authorization checks tied to a specific method."
    ),
    "out_of_order_workflow_execution": (
        "A multi-step REST workflow (e.g. create -> pay -> confirm) can be "
        "invoked out of sequence, or a token/identifier is reused across workflow "
        "stages, because the backend does not validate workflow state "
        "transitions."
    ),
    "insufficient_input_validation": (
        "Request parameters or bodies are processed without validating length, "
        "range, format, or type, without a request size limit, or using an XML "
        "parser vulnerable to XXE."
    ),
    "content_type_confusion": (
        "The response blindly copies the client's Accept header into the Content- "
        "Type header, or a request/response body's actual content does not match "
        "its declared content-type, risking misinterpretation or code execution "
        "by the consumer."
    ),
    "exposed_management_endpoint": (
        "An administrative or management REST endpoint is reachable from the "
        "public Internet without strong (e.g. multi-factor) authentication or "
        "network-level restriction."
    ),
    "verbose_error_disclosure": (
        "An error response returned to the client includes internal technical "
        "detail such as a stack trace, exception message, or other implementation "
        "hint rather than a generic error message."
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
