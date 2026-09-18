"""Vulnerable Dependency Management Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Vulnerable Dependency Management Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python vulnerable_dependency_management_classifier.py "some text to classify"
    python vulnerable_dependency_management_classifier.py --file path/to/content.txt
    echo "some text" | python vulnerable_dependency_management_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Vulnerable Dependency Management Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Vulnerable_Dependency_Management_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's case-by-case remediation
# approaches, governance guidance, and tooling section. Each description is
# written so Jev (the TypeSafe model) can distinguish it from neighboring
# categories.
CATEGORIES = {
    "patched_version_upgrade": (
        "Content discusses updating a vulnerable dependency to an "
        "already-released patched/fixed version and validating the upgrade "
        "with an automated test suite before pushing it to production."
    ),
    "vendor_delay_mitigation": (
        "Content discusses applying a temporary protective wrapper or extra "
        "input/output validation around calls to a known-vulnerable "
        "function while waiting for the vendor to release a fixed version."
    ),
    "unfixable_vendor_response": (
        "Content discusses a vendor refusing to fix an issue, not "
        "responding at all, or no patch being forthcoming, requiring the "
        "development team to write its own patch or submit a pull request "
        "upstream."
    ),
    "transitive_dependency_handling": (
        "Content discusses a vulnerability located in a transitive "
        "(indirect) dependency and the added difficulty of acting on it "
        "compared to acting on a direct, first-level project dependency."
    ),
    "backporting_fix": (
        "Content discusses backporting a security fix from a newer major "
        "version onto the older version line the project can actually run, "
        "isolating the security-relevant change from unrelated upstream "
        "refactoring."
    ),
    "risk_acceptance_governance": (
        "Content discusses a formal organizational decision to accept the "
        "risk of a known vulnerability, made by a Chief Risk Officer or "
        "CISO informed by technical analysis and the CVE's CVSS score."
    ),
    "cve_based_analysis": (
        "Content discusses using a CVE identifier or its description to "
        "determine the vulnerability class (e.g. SQL injection, RCE, XSS, "
        "XXE, CSRF) affecting a dependency and where in the application to "
        "apply patching."
    ),
    "suppression_vs_remediation": (
        "Content discusses distinguishing a real fix, verified by a test "
        "that fails against the unpatched dependency and passes against the "
        "patched one, from merely suppressing or ignoring a scanner alert "
        "or changing a version string without truly fixing the code."
    ),
    "dependency_scanning_tooling": (
        "Content discusses software composition analysis (SCA) tools used "
        "to detect vulnerable dependencies, such as OWASP Dependency-Check, "
        "npm audit, OWASP Dependency-Track, Trivy, or Grype."
    ),
    "early_lifecycle_scanning": (
        "Content discusses the benefit of scanning and managing dependency "
        "vulnerabilities from the start of a project, versus the much "
        "larger burden of retrofitting this practice onto an existing, "
        "mature project."
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
