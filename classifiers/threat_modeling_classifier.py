"""Threat Modeling Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Threat Modeling Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python threat_modeling_classifier.py "some text to classify"
    python threat_modeling_classifier.py --file path/to/content.txt
    echo "some text" | python threat_modeling_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Threat Modeling Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Threat_Modeling_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's process phases (system
# modeling, threat identification via STRIDE, response/mitigation, review)
# plus cloud threat modeling. Each description is written so Jev (the
# TypeSafe model) can distinguish it from neighboring categories -- be
# specific about what does and does not count.
CATEGORIES = {
    "missing_system_decomposition": (
        "The system being evaluated has not been modeled with a data flow diagram (DFD) "
        "or comparable artifact showing trust boundaries, data flows, data stores, "
        "processes, and external entities before threats are identified."
    ),
    "spoofing_authentication_threat": (
        "A threat involves an attacker impersonating a legitimate user or system, such as "
        "stealing and reusing an authentication token, violating authentication (STRIDE "
        "'Spoofing')."
    ),
    "tampering_integrity_threat": (
        "A threat involves unauthorized modification of data or code, such as abusing an "
        "application to perform unintended database updates, violating integrity (STRIDE "
        "'Tampering')."
    ),
    "repudiation_accounting_threat": (
        "A threat involves an actor denying having performed an action, or manipulating "
        "logs to cover their tracks, violating non-repudiation/accounting (STRIDE "
        "'Repudiation')."
    ),
    "information_disclosure_threat": (
        "A threat involves exposing data to parties who should not have access, such as "
        "extracting user account records from a database, violating confidentiality "
        "(STRIDE 'Information Disclosure')."
    ),
    "denial_of_service_threat": (
        "A threat involves degrading or blocking legitimate access to a system or account, "
        "such as locking out a user via repeated failed authentication attempts, violating "
        "availability (STRIDE 'Denial of Service')."
    ),
    "elevation_of_privilege_threat": (
        "A threat involves gaining capabilities or access beyond what was authorized, such "
        "as tampering with a JWT to change a role claim, violating authorization (STRIDE "
        "'Elevation of Privilege')."
    ),
    "unaddressed_threat_response": (
        "An identified threat has no documented response decision (mitigate, eliminate, "
        "transfer, or accept), or a chosen mitigation strategy is described only "
        "hypothetically rather than as an actionable, buildable requirement."
    ),
    "cloud_shared_responsibility_gap": (
        "Threat modeling for a cloud-native or hybrid system fails to account for the "
        "shared responsibility model, managed services, identity federation, or dynamic "
        "infrastructure such as IaC, serverless, or containers."
    ),
    "missing_review_and_validation": (
        "The threat model has not been reviewed and validated by all relevant "
        "stakeholders, or there is no way to confirm whether identified threats were "
        "addressed or whether agreed mitigations can actually be tested."
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
