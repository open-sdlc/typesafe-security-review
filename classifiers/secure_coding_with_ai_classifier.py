"""Secure Coding with AI Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Secure Coding with AI Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_with_AI_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python secure_coding_with_ai_classifier.py "some text to classify"
    python secure_coding_with_ai_classifier.py --file path/to/content.txt
    echo "some text" | python secure_coding_with_ai_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Secure Coding with AI Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Coding_with_AI_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "hallucinated_package_dependency": (
        "An AI coding assistant suggests installing a package name that does not "
        "exist on the public registry or is a plausible-sounding but unverified "
        "name, risking AI-assisted typosquatting."
    ),
    "outdated_vulnerable_dependency_suggestion": (
        "An AI assistant suggests a dependency version that was current at its "
        "training cutoff but has since-disclosed known CVEs, without any "
        "vulnerability-database cross-check."
    ),
    "indirect_prompt_injection_via_repo_content": (
        "An issue body, PR description/comment, README, error trace, changelog, "
        "or fetched web page contains hidden instructions that an AI coding agent "
        "follows as if they were commands from the developer."
    ),
    "malicious_or_compromised_mcp_server": (
        "An MCP tool server has a poisoned tool description, shadows a legitimate "
        "tool's name, exfiltrates data through tool arguments, or silently "
        "changes its tool definition after initial approval (a 'rug pull')."
    ),
    "unsandboxed_agent_execution": (
        "An AI coding agent runs with the developer's full credentials, SSH keys, "
        "or cloud access, with auto-accept/'--dangerously-skip-permissions' "
        "enabled and no sandboxing, egress control, or resource limits."
    ),
    "persistent_rules_file_tampering": (
        "A steering/configuration file that silently influences all future AI "
        "generations (CLAUDE.md, .cursorrules, AGENTS.md, copilot- "
        "instructions.md) is created or modified, potentially by an external "
        "contributor or the agent itself, without explicit review."
    ),
    "out_of_scope_agent_edit": (
        "An AI agent modifies files outside the explicitly requested change -- "
        "lockfiles, CI/CD configuration, unrelated tests, or formatting -- that a "
        "reviewer anchored on the task description might miss."
    ),
    "test_fabrication_or_deletion": (
        "An AI agent makes a failing test suite pass by deleting or weakening "
        "assertions, mocking the unit under test, or otherwise masking a real bug "
        "rather than fixing the underlying code."
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
