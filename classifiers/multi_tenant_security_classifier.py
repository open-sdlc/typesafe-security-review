"""Multi Tenant Security Cheat Sheet classifier built on the TypeSafe System
One API.

Classifies input text against sub-categories drawn from the OWASP
"Multi Tenant Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python multi_tenant_security_classifier.py "some text to classify"
    python multi_tenant_security_classifier.py --file path/to/content.txt
    echo "some text" | python multi_tenant_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Multi Tenant Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Multi_Tenant_Security_Cheat_Sheet.html"
)

# Sub-categories drawn directly from the cheat sheet's "Key Risks" section.
# Each description is written so Jev (the TypeSafe model) can distinguish it
# from neighboring categories -- be specific about what does and does not
# count.
CATEGORIES = {
    "cross_tenant_data_leakage": (
        "A bug or misconfiguration exposes one tenant's data to a different "
        "tenant, such as a query missing a tenant filter or a broken access "
        "control policy."
    ),
    "tenant_impersonation": (
        "An attacker or client is able to act as, or gain access to, another "
        "tenant's context, session, or resources rather than merely reading "
        "leaked data."
    ),
    "broken_tenant_isolation": (
        "Separation between tenants at the database, cache, storage, or "
        "compute layer is insufficient, e.g. missing row-level security, "
        "shared caches without tenant keys, or shared compute without "
        "boundaries."
    ),
    "tenant_idor": (
        "A tenant-scoped resource is accessed by guessing or manipulating a "
        "resource/tenant ID in a request without verifying the authenticated "
        "principal's membership in that tenant (Insecure Direct Object "
        "Reference)."
    ),
    "noisy_neighbor_dos": (
        "One tenant consumes a disproportionate share of shared compute, "
        "database, or bandwidth resources, degrading availability or "
        "performance for other tenants (resource-exhaustion DoS)."
    ),
    "cross_tenant_privilege_escalation": (
        "An admin or platform-level function is exploited to gain access to, "
        "or elevate privileges within, a different tenant's data or "
        "configuration than the one the caller belongs to."
    ),
    "tenant_context_injection": (
        "A client-supplied tenant identifier in a request header, token, or "
        "body is trusted as a selector without verifying it against the "
        "authenticated principal's actual, server-verified tenant membership."
    ),
    "shared_resource_poisoning": (
        "A tenant is able to poison a cache, injection into a shared message "
        "queue, or pollute shared storage in a way that affects the data or "
        "behavior seen by other tenants."
    ),
    "insecure_tenant_lifecycle": (
        "Tenant onboarding or offboarding is incomplete, leaving unauthorized "
        "residual access, orphaned resources, or data retained beyond policy "
        "after a tenant is removed."
    ),
    "tenant_audit_compliance_gap": (
        "Logging or auditing is not tenant-specific enough to satisfy "
        "regulatory or compliance requirements, making it impossible to prove "
        "which tenant performed or was affected by an action."
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
