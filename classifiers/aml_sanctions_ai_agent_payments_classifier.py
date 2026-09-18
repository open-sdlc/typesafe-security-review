"""AML Sanctions AI Agent Payments Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"AML Sanctions AI Agent Payments Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/AML_Sanctions_AI_Agent_Payments_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python aml_sanctions_ai_agent_payments_classifier.py "some text to classify"
    python aml_sanctions_ai_agent_payments_classifier.py --file path/to/content.txt
    echo "some text" | python aml_sanctions_ai_agent_payments_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "AML Sanctions AI Agent Payments Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/AML_Sanctions_AI_Agent_Payments_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "unverified_agent_identity": (
        "An AI agent is granted access to sanctions screening or payment "
        "endpoints based on a self-declared identity header (e.g. X-Agent-ID) or "
        "transport-layer TLS certificate alone, without a cryptographically "
        "verified identity credential (signed passport, ECDSA key, verifiable "
        "credential) bound at the message level."
    ),
    "screening_bypass_or_threshold_tamper": (
        "A payment or transaction is initiated by an agent without first "
        "completing sanctions screening against OFAC/UK/EU/UN lists, or the agent "
        "is able to override, lower, or otherwise tamper with the institution's "
        "configured minimum match threshold."
    ),
    "unsigned_screening_result_tampering": (
        "A sanctions screening request or result is transmitted or stored "
        "unsigned, allowing a compromised intermediary to alter a match verdict "
        "(e.g. changing 'match' to 'no-match') without detection."
    ),
    "unscreened_agent_operator": (
        "The organization or developer that operates/deploys an AI agent (its "
        "declared operator) is not itself screened or periodically re-screened "
        "against sanctions lists, or the agent is allowed to operate with no "
        "declared operator at all."
    ),
    "broken_tamper_evident_audit_trail": (
        "Agent-initiated screening or payment actions are logged only via "
        "ordinary application logs (console.log, syslog) rather than a "
        "hash-chained, cryptographically signed audit trail that binds the "
        "agent's identity to each screening request and result, or the hash chain "
        "has gaps."
    ),
    "fail_open_on_screening_failure": (
        "A payment or transaction is allowed to proceed when the sanctions "
        "screening service times out, errors, returns an ambiguous result, or is "
        "otherwise unavailable, instead of being denied (fail-closed)."
    ),
    "agent_rate_limit_gaps": (
        "Agent-initiated screening or payment requests are rate-limited only by "
        "IP address rather than by cryptographic agent identity, or "
        "low-trust/newly registered agents are not subjected to stricter limits "
        "than verified high-trust agents, enabling probing or sybil abuse."
    ),
    "stale_cached_screening_results": (
        "An agent caches or reuses a sanctions screening result beyond a short, "
        "configured time window, creating a compliance gap when the underlying "
        "sanctions lists are updated."
    ),
    "excessive_data_to_third_party_screener": (
        "Agent private keys, full identity credentials, or more data than the "
        "minimum required for a match check are sent to a third-party hosted "
        "sanctions screening provider, instead of applying data minimization."
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
