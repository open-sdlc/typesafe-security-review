"""Software Supply Chain Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Software Supply Chain Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python software_supply_chain_security_classifier.py "some text to classify"
    python software_supply_chain_security_classifier.py --file path/to/content.txt
    echo "some text" | python software_supply_chain_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Software Supply Chain Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Software_Supply_Chain_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's four threat categories (source
# code, build environment, dependency, deployment/runtime) and mitigation
# sections. Each description is written so Jev (the TypeSafe model) can
# distinguish it from neighboring categories -- be specific about what does
# and does not count.
CATEGORIES = {
    "source_code_integrity_threat": (
        "The integrity of source code is threatened via version control system (VCS) "
        "exploits, introduction of malicious or vulnerable code into a codebase, or "
        "building/deploying code from an unauthorized branch."
    ),
    "build_environment_compromise": (
        "The build process or artifact is tampered with without altering the underlying "
        "source, such as build cache poisoning, compromise of a privileged build-tool "
        "account, or publishing an artifact built from an untrusted source."
    ),
    "dependency_confusion_or_vulnerable_package": (
        "A direct or transitive software dependency is vulnerable, compromised, or "
        "maliciously substituted (e.g. dependency confusion attack), and is consumed "
        "without vetting, monitoring for known CVEs, or version pinning."
    ),
    "deployment_runtime_compromise": (
        "The deployment process or runtime environment is exploited, such as compromising "
        "a privileged CI/CD account, deploying software misconfigurations, or shipping "
        "compromised/backdoored binaries to production."
    ),
    "weak_access_control_credential_handling": (
        "Privileged accounts used for source control, build, or deployment lack strong "
        "access control (least privilege, MFA, credential rotation), or credentials are "
        "stored/transmitted in clear text or committed to source control."
    ),
    "insufficient_logging_monitoring_ssc": (
        "Systems in the software supply chain (VCS, build tools, artifact repositories, "
        "delivery mechanisms) fail to log authentication attempts and configuration "
        "changes, or such logs are not actively monitored for anomalous behavior."
    ),
    "unvetted_third_party_component": (
        "A third-party vendor, open-source project, or software component is incorporated "
        "without assessing its maintenance activity, security history, test coverage, or "
        "vulnerability disclosure process before adoption."
    ),
    "unvetted_development_tooling": (
        "IDEs, code editors, plugins, or extensions used in the development process are "
        "adopted without security vetting or endpoint protection, creating an attack vector "
        "through the developer's own tooling."
    ),
    "missing_sbom_or_lockfile_pinning": (
        "The organization lacks a Software Bill of Materials (SBOM) or dependency lockfile/"
        "version pinning, making it difficult to know which dependency versions are in use "
        "or to prevent an unverified version from being pulled in."
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
