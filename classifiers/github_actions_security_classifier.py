"""GitHub Actions Security Cheat Sheet classifier built on the TypeSafe System
One API.

Classifies input text against sub-categories drawn from the OWASP
"GitHub Actions Security Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python github_actions_security_classifier.py "some text to classify"
    python github_actions_security_classifier.py --file path/to/content.txt
    echo "some text" | python github_actions_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "GitHub Actions Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "GitHub_Actions_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's introduction (secrets
# exfiltration, GITHUB_TOKEN compromise, cache poisoning), repository
# hardening, dangerous triggers, and secure secrets handling sections.
CATEGORIES = {
    "secrets_exfiltration_risk": (
        "A workflow could leak long-lived credentials (cloud provider keys, "
        "package registry tokens) via logs, external network calls, or "
        "artifacts, especially through attacker-controlled code execution in "
        "CI/CD."
    ),
    "github_token_write_permission_abuse": (
        "The default GITHUB_TOKEN is granted write permissions beyond what a "
        "workflow needs, risking modification of repository contents, "
        "releases, or other resources if the token is compromised."
    ),
    "actions_cache_poisoning": (
        "A workflow reuses cached data across runs in a way that lets an "
        "attacker inject malicious content into the cache, which a later "
        "privileged (e.g. release) workflow then restores and executes."
    ),
    "dangerous_workflow_triggers": (
        "A workflow uses pull_request_target, workflow_run, or issue_comment "
        "triggers and checks out or executes untrusted PR code in a context "
        "that has access to secrets or a write-scoped GITHUB_TOKEN."
    ),
    "untrusted_or_unpinned_third_party_actions": (
        "A third-party GitHub Action or reusable workflow is referenced by a "
        "mutable tag/branch instead of a pinned, verified commit SHA, or its "
        "origin/maintainers were not vetted (impostor-commit risk)."
    ),
    "self_hosted_runner_exposure": (
        "A self-hosted runner is used with a public repository or accepts "
        "workflows from forked pull requests without manual approval, "
        "risking persistent compromise of internal infrastructure."
    ),
    "script_injection_via_untrusted_context": (
        "User-controlled context (e.g. a pull request title or issue body) "
        "is interpolated directly into a run: step instead of being passed "
        "through an intermediate environment variable, enabling script "
        "injection."
    ),
    "ai_assistant_prompt_injection_in_ci": (
        "An AI assistant running inside a CI/CD workflow (e.g. for PR review "
        "or issue triage) can be manipulated via prompt injection from "
        "untrusted input, potentially leading to secret exfiltration or "
        "unauthorized repository actions."
    ),
    "excessive_default_permissions": (
        "Workflow or job-level `permissions` are not minimized (e.g. "
        "`permissions: {}` is not set as the default with explicit grants "
        "added only where required)."
    ),
    "missing_static_analysis_or_branch_protection": (
        "The repository lacks CodeQL/Zizmor scanning of workflow files, or "
        "lacks branch protection such as required reviews, status checks, or "
        "signed commits before merging."
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
