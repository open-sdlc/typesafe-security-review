"""AI Agent Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"AI Agent Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python ai_agent_security_classifier.py "some text to classify"
    python ai_agent_security_classifier.py --file path/to/content.txt
    echo "some text" | python ai_agent_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "AI Agent Security Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "tool_abuse_privilege_escalation": (
        "An AI agent is granted an overly permissive tool (e.g. unrestricted "
        "shell access, wildcard file paths) or exploits a tool's excessive "
        "permissions to perform an action or access a resource beyond what its "
        "specific task requires."
    ),
    "memory_poisoning": (
        "Malicious or unvalidated data is persisted into an agent's long-term or "
        "session memory -- without sanitization, size limits, integrity checks, "
        "or expiration -- so it can influence a future session, another user, or "
        "bypass isolation between users."
    ),
    "goal_hijacking": (
        "An agent's objective is manipulated (via injected instructions or "
        "crafted context) so it pursues attacker-chosen goals while its output or "
        "reasoning still appears legitimate to a human reviewer."
    ),
    "excessive_autonomy_high_impact": (
        "An agent executes a high-impact, irreversible, financial, "
        "administrative, or externally visible action (fund transfer, deletion, "
        "production deployment) without independent human-in-the-loop approval, "
        "action-binding to a specific actor/target, or step-up authentication."
    ),
    "decision_approval_manipulation": (
        "An attacker influences an agent's risk score, model confidence output, "
        "or approval threshold in order to make an unsafe or unauthorized action "
        "appear auto-approvable."
    ),
    "cascading_multi_agent_failure": (
        "A compromised or manipulated agent propagates an attack to other agents "
        "in a multi-agent system through unvalidated inter-agent messages, "
        "missing trust boundaries, or lack of circuit breakers between agents."
    ),
    "denial_of_wallet": (
        "An attacker triggers unbounded agent loops, excessive tool calls, or "
        "repeated expensive operations designed to run up API or compute costs "
        "(Denial of Wallet) rather than to deny availability outright."
    ),
    "sensitive_data_exposure_agent_context": (
        "PII, credentials, API keys, or other confidential data are inadvertently "
        "included in an agent's context window, tool-call parameters, memory, or "
        "logs without redaction."
    ),
    "supply_chain_agent_compromise": (
        "A third-party tool, plugin, API, or external data source integrated into "
        "an agent's toolchain is compromised or malicious, and the agent trusts "
        "its output without validation."
    ),
    "agent_prompt_injection": (
        "External or user-supplied content (websites, documents, emails, tool "
        "outputs) contains instructions that hijack the agent's behavior, whether "
        "injected directly by the user or indirectly via retrieved/external data "
        "the agent is asked to process."
    ),
    "output_validation_bypass": (
        "An agent's output or proposed tool call is executed or displayed without "
        "schema validation, allowed-tool checks, or content-safety filtering, "
        "letting disallowed actions or data-exfiltration attempts (e.g. encoding "
        "secrets into a URL or webhook payload) through."
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
