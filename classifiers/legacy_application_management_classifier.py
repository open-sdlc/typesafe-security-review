"""Legacy Application Management Cheat Sheet classifier built on the TypeSafe
System One API.

Classifies input text against sub-categories drawn from the OWASP
"Legacy Application Management Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Legacy_Application_Management_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python legacy_application_management_classifier.py "some text to classify"
    python legacy_application_management_classifier.py --file path/to/content.txt
    echo "some text" | python legacy_application_management_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Legacy Application Management Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Legacy_Application_Management_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_inventory_documentation": (
        "The organization lacks a maintained inventory of its legacy "
        "applications, such as version numbers, configuration details, "
        "hosting locations, or a Software Bill of Materials (SBOM)."
    ),
    "absent_risk_assessment": (
        "No formal risk assessment or threat modeling has been performed to "
        "understand the exposure posed by a legacy application or its "
        "specific components (e.g. particular API routes or open ports)."
    ),
    "insufficient_network_or_access_restriction": (
        "A legacy application is not isolated via network segmentation, IP "
        "allow-listing, or air-gapping, despite the cheat sheet's guidance "
        "that legacy applications should be treated as inherently high "
        "risk."
    ),
    "weak_authentication_authorization_controls": (
        "A legacy application's authentication or authorization controls "
        "are not hardened with least privilege, a reduced feature set for "
        "high-risk functionality, or an Identity Provider (IdP), despite "
        "being high risk."
    ),
    "unpatched_end_of_life_software": (
        "A legacy application has reached End-of-Life (EoL) or is missing "
        "regular vulnerability scanning and timely patch management for "
        "known vulnerabilities."
    ),
    "unencrypted_legacy_data_storage": (
        "Data handled by a legacy application is not encrypted at rest or "
        "in transit, particularly where the application is restricted to "
        "older, plaintext-only network protocols."
    ),
    "loss_of_institutional_knowledge": (
        "Risk that the expertise needed to maintain, troubleshoot, or "
        "remediate a legacy application is concentrated in very few staff "
        "or is not documented (e.g. missing troubleshooting guides)."
    ),
    "missing_migration_change_management_plan": (
        "The organization lacks a documented change-management plan with a "
        "budget, timeline, and concrete steps for migrating away from or "
        "decommissioning the legacy application."
    ),
    "inadequate_monitoring_or_incident_response": (
        "A legacy application lacks adequate security monitoring/log "
        "integration with SIEM tooling, or lacks an incident-response "
        "playbook tailored to its elevated risk profile."
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
