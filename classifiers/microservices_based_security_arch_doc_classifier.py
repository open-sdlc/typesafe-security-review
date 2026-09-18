"""Microservices based Security Arch Doc Cheat Sheet classifier built on the
TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Microservices based Security Arch Doc Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Microservices_based_Security_Arch_Doc_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python microservices_based_security_arch_doc_classifier.py "some text to classify"
    python microservices_based_security_arch_doc_classifier.py --file path/to/content.txt
    echo "some text" | python microservices_based_security_arch_doc_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Microservices based Security Arch Doc Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Microservices_based_Security_Arch_Doc_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_least_privilege_documentation": (
        "Architecture documentation fails to record what minimal scopes, API "
        "keys, or database/queue grants each microservice actually needs, "
        "preventing enforcement of the principle of least privilege."
    ),
    "undocumented_data_flows": (
        "The data passed between microservices, and which services invoke "
        "which other services, is not documented, preventing data leakage "
        "analysis of what sensitive information moves across the system."
    ),
    "unclassified_sensitive_storage": (
        "Data storages or message queues that contain sensitive data are not "
        "identified or labeled, so it is unclear which datastores need "
        "additional protection."
    ),
    "unmapped_attack_surface": (
        "There is no inventory of microservice endpoints that need to be "
        "covered during security testing, leaving the application's attack "
        "surface unmapped."
    ),
    "missing_service_inventory": (
        "Application-functionality or infrastructure services lack a "
        "documented catalog entry (service name/ID, owning team, source "
        "repository link, API definition, or runbook)."
    ),
    "undocumented_service_dependencies": (
        "Synchronous or asynchronous service-to-service communications "
        "(protocol/framework used, purpose, data exchanged) between "
        "microservices are not captured in architecture documentation."
    ),
    "missing_architecture_diagram": (
        "There is no graphical representation (service call graph or data "
        "flow diagram) of the building blocks and their relations, making the "
        "architecture hard to reason about for threat modeling."
    ),
    "unclassified_data_assets": (
        "Data assets processed by the system (e.g. 'User information', "
        "'Payment') are not identified and assigned a protection level such "
        "as PII or confidential, nor mapped to the storages that hold them."
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
