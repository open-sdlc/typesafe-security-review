"""gRPC Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"gRPC Security Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/gRPC_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python grpc_security_classifier.py "some text to classify"
    python grpc_security_classifier.py --file path/to/content.txt
    echo "some text" | python grpc_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "gRPC Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "gRPC_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's Transport Security,
# Authentication/Authorization, Input Validation, Rate Limiting, Error
# Handling, and Service Discovery/Reflection sections.
CATEGORIES = {
    "missing_transport_encryption": (
        "A gRPC service is deployed without TLS (or with weak protocol "
        "versions/cipher suites), exposing traffic to eavesdropping or "
        "man-in-the-middle attacks."
    ),
    "missing_mutual_tls": (
        "Service-to-service gRPC communication does not use mutual TLS "
        "(mTLS) to verify both client and server certificates, or uses "
        "long-lived certificates without rotation."
    ),
    "weak_authentication_tokens": (
        "gRPC method calls rely on missing/weak JWT or API key validation, "
        "long-lived tokens without expiration/refresh, or credentials passed "
        "as method parameters instead of metadata headers."
    ),
    "missing_method_level_authorization": (
        "A gRPC service method lacks a granular, role-based authorization "
        "check enforcing least privilege before executing the requested "
        "operation."
    ),
    "input_validation_and_injection_gaps": (
        "Protocol Buffer message fields are not validated (e.g. no "
        "protoc-gen-validate rules/allowlists), or user input reaches a "
        "database or system call without parameterization, risking "
        "injection or malformed-data processing."
    ),
    "unbounded_message_size_dos": (
        "The gRPC server does not set MaxRecvMsgSize/MaxSendMsgSize or "
        "stream/message-count limits, allowing a client to send arbitrarily "
        "large or numerous messages and exhaust server memory."
    ),
    "missing_rate_limiting_or_timeouts": (
        "The gRPC service lacks per-client request rate limiting or "
        "client/server-side timeouts, leaving it open to request flooding or "
        "long-running resource exhaustion."
    ),
    "verbose_error_disclosure": (
        "A gRPC method returns detailed internal error information to the "
        "caller instead of a generic message with an appropriate status code "
        "(e.g. INVALID_ARGUMENT, UNAUTHENTICATED), while logging details only "
        "server-side."
    ),
    "reflection_service_exposure": (
        "gRPC server reflection is left enabled in a production environment, "
        "letting a client enumerate all service methods and message schemas."
    ),
    "insecure_service_discovery": (
        "The service discovery mechanism (e.g. Consul, Kubernetes) is used "
        "without mTLS or RBAC protections, risking injection of malicious "
        "service endpoints or interception of service information."
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
