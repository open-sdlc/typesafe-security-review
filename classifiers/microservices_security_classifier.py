"""Microservices Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Microservices Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python microservices_security_classifier.py "some text to classify"
    python microservices_security_classifier.py --file path/to/content.txt
    echo "some text" | python microservices_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Microservices Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Microservices_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "edge_only_authorization": (
        "Authorization is enforced only at the API gateway/edge layer with no "
        "service-level checks, creating a single point of decision that "
        "violates 'defense in depth' and is vulnerable to gateway bypass if an "
        "internal service becomes directly reachable."
    ),
    "decentralized_hardcoded_authz": (
        "Access control rules and attributes are hardcoded directly in each "
        "microservice's source code (decentralized pattern) rather than "
        "externalized into a policy language, requiring a code change and "
        "redeploy whenever authorization logic must change."
    ),
    "missing_mutual_authentication": (
        "Internal, service-to-service calls lack mutual authentication (e.g. "
        "mTLS), allowing a direct, anonymous connection to an internal "
        "microservice that bypasses the API gateway entirely."
    ),
    "raw_access_token_passthrough": (
        "The external caller's own access token (e.g. a cookie, JWT, or "
        "OAuth2 token) is reused unchanged and forwarded as-is to downstream "
        "internal microservices, risking leakage of the external token and "
        "requiring every internal service to understand external token formats."
    ),
    "unsigned_identity_propagation": (
        "The caller's identity/context (user ID, roles) is propagated between "
        "microservices as plain, unsigned, or self-signed data (e.g. a raw "
        "header or JSON blob) that a malicious or compromised calling service "
        "could forge to claim any user or role."
    ),
    "centralized_pdp_bottleneck": (
        "A centralized policy decision point (PDP) reached via a network call "
        "for every authorization check introduces added latency and becomes a "
        "single point of failure unless it is deployed in a highly available, "
        "cached, or embedded configuration."
    ),
    "missing_defense_in_depth_layers": (
        "Authorization is enforced at only one layer (e.g. only gateway, or "
        "only business code) instead of combining gateway-level, shared "
        "library/service-level, and business-logic-level checks as recommended "
        "defense in depth for microservices."
    ),
    "custom_authorization_solution_risk": (
        "The organization builds and maintains a bespoke, non-standard "
        "authorization solution/protocol instead of adopting a widely-used "
        "standard, incurring the cost of custom SDKs per language and lacking "
        "community/security-review support."
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
