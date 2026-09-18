"""Infrastructure as Code Security Cheat Sheet classifier built on the
TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Infrastructure as Code Security Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python infrastructure_as_code_security_classifier.py "some text to classify"
    python infrastructure_as_code_security_classifier.py --file path/to/content.txt
    echo "some text" | python infrastructure_as_code_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Infrastructure as Code Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Infrastructure_as_Code_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's Develop and Distribute, Deploy,
# and Runtime security-best-practices sections for Infrastructure as Code.
CATEGORIES = {
    "hardcoded_secrets_in_iac": (
        "Confidential data such as application tokens, passwords, or SSH "
        "keys is stored in plaintext inside IaC files or committed to "
        "version control (e.g. Git) instead of a secrets manager."
    ),
    "missing_static_analysis_scanning": (
        "IaC code (Terraform, Kubernetes manifests, Dockerfiles, etc.) is not "
        "scanned with IDE plugins or static analysis tools (e.g. TFLint, "
        "Checkov, kubescan, Snyk) to catch misconfigurations early."
    ),
    "missing_container_image_scanning": (
        "Container images built or referenced by the IaC pipeline are not "
        "scanned for vulnerabilities (e.g. with Clair, Trivy, Anchore, "
        "Dagda) before deployment."
    ),
    "excessive_iac_permissions": (
        "The IaC pipeline, its users, or the resources it provisions are not "
        "restricted to least-privilege access, so more principals than "
        "necessary can create/update/run/delete infrastructure or resources "
        "get over-permissioned by default."
    ),
    "unscanned_open_source_dependencies": (
        "Open source dependencies used by the IaC (OS packages, libraries) "
        "are not analyzed for known vulnerabilities using tools like "
        "BlackDuck, Snyk, or WhiteSource Bolt."
    ),
    "missing_artifact_signing_or_provenance": (
        "Build artifacts are not digitally signed at build time, or their "
        "signatures/provenance are not validated before use, allowing "
        "tampering between build and runtime."
    ),
    "poor_inventory_and_tagging": (
        "Cloud resources are commissioned, decommissioned, or left running "
        "without proper labeling/tagging and inventory tracking, leading to "
        "untracked 'ghost' resources."
    ),
    "missing_runtime_monitoring_or_logging": (
        "Deployed infrastructure lacks security/audit logging, continuous "
        "monitoring, or runtime threat detection (e.g. Falco) to catch "
        "security or compliance violations."
    ),
    "lack_of_immutable_infrastructure": (
        "Infrastructure is patched or modified in place rather than being "
        "redeployed from an updated, versioned specification with the old "
        "infrastructure decommissioned."
    ),
    "insecure_decommissioning": (
        "When a resource is deleted, its underlying configuration and data "
        "are not securely erased, or it is not fully removed from runtime and "
        "inventory management systems."
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
