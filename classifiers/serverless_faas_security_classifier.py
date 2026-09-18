"""Serverless FaaS Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Serverless FaaS Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Serverless_FaaS_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python serverless_faas_security_classifier.py "some text to classify"
    python serverless_faas_security_classifier.py --file path/to/content.txt
    echo "some text" | python serverless_faas_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Serverless FaaS Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Serverless_FaaS_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "Key Risks" and "Best Practices"
# sections. Each description is written so Jev (the TypeSafe model) can
# distinguish it from neighboring categories -- be specific about what does
# and does not count.
CATEGORIES = {
    "over_permissioned_function": (
        "The function is described as having broad IAM roles or wildcard ('*') action/"
        "resource policies, rather than the minimal, scoped permissions it actually needs "
        "(violation of least privilege)."
    ),
    "unvalidated_event_input": (
        "Event payloads from triggers such as API Gateway, S3, Pub/Sub, or IoT are treated "
        "as trusted without input validation/sanitization, opening the door to injection "
        "attacks (SQLi, XSS, JSON injection, deserialization) via the event data."
    ),
    "cold_start_data_leakage": (
        "Sensitive data persists in global/static variables or leftover files (e.g. /tmp) "
        "across function invocations, or timing differences between cold and warm starts "
        "create a side-channel that leaks information."
    ),
    "function_chaining_abuse": (
        "A compromised or malicious function invokes other functions or propagates "
        "attacker-controlled input across a chain of function calls, escalating the blast "
        "radius of a single compromised function."
    ),
    "shared_environment_multitenancy_risk": (
        "Multiple tenants, invocations, or workloads share the same underlying execution "
        "environment (e.g. reused /tmp storage or container) in a way that could leak data "
        "between unrelated executions."
    ),
    "hardcoded_secrets_in_function": (
        "Secrets such as API keys, passwords, or credentials are hardcoded in function "
        "source code or stored as plain platform configuration/environment variables "
        "instead of being fetched at runtime from a secrets vault."
    ),
    "excessive_network_egress": (
        "The function has broader outbound network access than required, such as default "
        "internet egress instead of being placed in a private subnet with restricted, "
        "controlled network access."
    ),
    "insecure_function_invocation": (
        "Function triggers (API Gateway, Pub/Sub, S3, IoT) lack proper authentication/"
        "authorization enforcement, function-to-function calls are unsigned, or there is no "
        "rate limiting/throttling to prevent abuse or denial-of-service."
    ),
    "supply_chain_dependency_risk": (
        "The deployment package includes unscanned or unverified third-party dependencies, "
        "oversized deployment artifacts, or unsigned packages/layers that could introduce "
        "vulnerable or malicious code."
    ),
    "insufficient_logging_monitoring": (
        "Function invocations and events are not logged to a centralized system, or logs "
        "contain unmasked secrets and personally identifiable information (PII) instead of "
        "redacted values."
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
