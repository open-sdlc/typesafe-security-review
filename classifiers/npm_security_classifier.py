"""NPM Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"NPM Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python npm_security_classifier.py "some text to classify"
    python npm_security_classifier.py --file path/to/content.txt
    echo "some text" | python npm_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "NPM Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "NPM_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "secret_leakage_via_publish": (
        "Secrets, API keys, or passwords leak into a published npm package "
        "because of a mismatch between .gitignore and .npmignore, or because "
        "the 'files' allowlist in package.json was not used to control what "
        "is packed."
    ),
    "missing_lockfile_enforcement": (
        "Dependency installation does not enforce the lockfile (e.g. skips "
        "`npm ci` or `yarn install --frozen-lockfile`), allowing an "
        "inconsistency between package.json and the lockfile to silently pull "
        "different dependency versions."
    ),
    "malicious_lifecycle_scripts": (
        "Package install/postinstall/preinstall lifecycle scripts are allowed "
        "to run arbitrary code automatically (e.g. `--ignore-scripts` is not "
        "used and no allowlist restricts which packages may run scripts), "
        "enabling supply-chain attacks like token harvesting."
    ),
    "unvetted_vulnerable_dependencies": (
        "Third-party npm dependencies are added or upgraded without auditing "
        "them for known vulnerabilities, reviewing changelogs, or running "
        "software composition analysis (e.g. `npm audit`)."
    ),
    "insecure_registry_or_proxy_config": (
        "The project pulls packages from an untrusted or unpinned registry "
        "instead of a vetted mirror or private registry/proxy, or does not "
        "restrict which registries are used for installs."
    ),
    "missing_supply_chain_provenance": (
        "Published build artifacts lack a software bill of materials (SBOM), "
        "signing, or build provenance, making it impossible for consumers to "
        "verify that the package was built from the expected source."
    ),
    "missing_2fa_on_publish_account": (
        "The npm account or organization used to publish packages does not "
        "require two-factor authentication for login or for write actions "
        "like publishing and managing tokens."
    ),
    "unrestricted_ci_publish_tokens": (
        "CI/CD or publisher tokens used to publish npm packages are not "
        "scoped, restricted to specific workflows/IP ranges, or rotated "
        "regularly, increasing the blast radius if a token leaks."
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
