"""Dependency Graph SBOM Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Dependency Graph & SBOM Best Practices Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python dependency_graph_sbom_classifier.py "some text to classify"
    python dependency_graph_sbom_classifier.py --file path/to/content.txt
    echo "some text" | python dependency_graph_sbom_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Dependency Graph SBOM Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Dependency_Graph_SBOM_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_or_ad_hoc_sbom_generation": (
        "No Software Bill of Materials (SBOM) is generated for a release, or "
        "it is only produced manually/ad-hoc rather than automatically during "
        "the build, risking an inaccurate or stale component inventory."
    ),
    "non_standard_or_incomplete_sbom_format": (
        "An SBOM is produced in a non-standard, proprietary, or ad-hoc format "
        "rather than a recognized standard such as SPDX or CycloneDX, "
        "hindering interoperability with SCA tooling."
    ),
    "incomplete_sbom_metadata": (
        "An SBOM is missing key required elements such as component "
        "version, package URL (purl), checksums, supplier/origin, license "
        "information, or the direct-vs-transitive dependency relationship."
    ),
    "unsigned_sbom_missing_provenance": (
        "An SBOM or its associated build artifact is not cryptographically "
        "signed or attested (e.g. via Cosign/Sigstore/in-toto), leaving it "
        "vulnerable to forgery or tampering since it cannot be bound to the "
        "trusted build that produced it."
    ),
    "missing_sbom_versioning_or_retention": (
        "SBOMs are not versioned, archived, or retained over time in a "
        "trusted store, hindering audit trails and incident response for "
        "past releases."
    ),
    "unvetted_supplier_or_third_party_sbom": (
        "A third-party vendor or supplier component is incorporated without "
        "requiring or validating an accompanying SBOM, undermining supply "
        "chain visibility and governance."
    ),
    "missing_vulnerability_triage_workflow": (
        "There is no defined process mapping known CVEs to SBOM components, "
        "prioritizing direct vs transitive exposure, or using VEX data to "
        "determine real-world exploitability before remediation."
    ),
    "transitive_dependency_blind_spot": (
        "The dependency graph does not surface or visualize transitive "
        "(indirect) dependencies, making it difficult to understand why a "
        "vulnerable nested package was pulled into the build or how to "
        "remediate it."
    ),
    "missing_sbom_policy_or_governance": (
        "The organization lacks a written SBOM policy defining required "
        "formats, fields, storage/retention rules, signing requirements, or "
        "SLAs for vulnerability response."
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
