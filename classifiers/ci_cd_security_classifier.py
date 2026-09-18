"""CI/CD Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"CI/CD Security Cheat Sheet" cheat sheet (based on the OWASP Top 10 CI/CD
Security Risks):
https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python ci_cd_security_classifier.py "some text to classify"
    python ci_cd_security_classifier.py --file path/to/content.txt
    echo "some text" | python ci_cd_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "CI CD Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "insufficient_flow_control": (
        "Pipeline changes or code can move toward production without required "
        "gates, e.g. auto-merge rules, missing mandatory pull request review, "
        "or the ability to bypass a review step before code is built or "
        "deployed (CICD-SEC-1)."
    ),
    "inadequate_identity_access_management": (
        "Weak or missing identity and access controls for CI/CD systems, such "
        "as absent MFA, shared/local accounts instead of a centralized IdP, "
        "over-broad default permissions, or poor lifecycle management "
        "(joiner/mover/leaver) of pipeline identities (CICD-SEC-2)."
    ),
    "dependency_chain_abuse": (
        "Risk from third-party or transitive dependencies pulled into the "
        "build, such as typosquatting, dependency confusion, or compromised "
        "upstream packages introduced through the software supply chain "
        "(CICD-SEC-3)."
    ),
    "poisoned_pipeline_execution": (
        "An attacker is able to inject and execute arbitrary commands within "
        "the CI/CD pipeline by manipulating pipeline definition files, build "
        "scripts, or configuration stored in or referenced by the repository "
        "(CICD-SEC-4)."
    ),
    "insufficient_pipeline_based_access_controls": (
        "A pipeline or its identity has excessive access to resources beyond "
        "what that specific pipeline step requires, violating least privilege "
        "at the pipeline level rather than the individual user level "
        "(CICD-SEC-5)."
    ),
    "insufficient_credential_hygiene": (
        "Secrets such as API keys, tokens, or passwords are hardcoded in "
        "repositories or CI configuration files, printed to logs/console, "
        "stored in cleartext, or otherwise mismanaged instead of being kept in "
        "a dedicated secrets manager (CICD-SEC-6)."
    ),
    "insecure_system_configuration": (
        "CI/CD components such as SCM systems or automation servers (Jenkins, "
        "TeamCity, CircleCI) are left with insecure default vendor settings, "
        "unpatched software, or unhardened OS/container configuration "
        "(CICD-SEC-7)."
    ),
    "ungoverned_third_party_services": (
        "Third-party services, plugins, integrations, or marketplace actions "
        "are connected to the CI/CD environment without proper vetting, "
        "approval, or governance of the access they are granted (CICD-SEC-8)."
    ),
    "improper_artifact_integrity_validation": (
        "Build artifacts, container images, or packages are consumed or "
        "deployed without verifying their integrity or provenance, e.g. "
        "missing signature/checksum validation that would catch tampering "
        "after the build step (CICD-SEC-9)."
    ),
    "insufficient_logging_and_visibility": (
        "The CI/CD environment lacks adequate logging, monitoring, or "
        "alerting, making it difficult to detect malicious activity, "
        "unauthorized configuration changes, or investigate an incident after "
        "the fact (CICD-SEC-10)."
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
