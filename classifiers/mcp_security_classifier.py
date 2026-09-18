"""MCP Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"MCP (Model Context Protocol) Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python mcp_security_classifier.py "some text to classify"
    python mcp_security_classifier.py --file path/to/content.txt
    echo "some text" | python mcp_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "MCP Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "MCP_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "tool_poisoning": (
        "Malicious or manipulative instructions are hidden inside an MCP "
        "tool's description, parameter schema, or return values, intended "
        "to steer the LLM's behavior when it reads the tool definition."
    ),
    "rug_pull_definition_change": (
        "An MCP server changes its tool definitions after a user has "
        "already reviewed and approved them, turning a previously trusted "
        "tool malicious without a new consent prompt."
    ),
    "tool_shadowing_cross_server": (
        "A malicious MCP server's tool description manipulates how the "
        "agent behaves with, or invokes, tools belonging to a different, "
        "trusted MCP server (cross-origin escalation)."
    ),
    "confused_deputy_excessive_privilege": (
        "An MCP server executes an action using its own broad privileges or "
        "credentials rather than checking and applying the actual "
        "permissions of the requesting user."
    ),
    "prompt_injection_via_tool_output": (
        "A tool's return value contains instruction-like content (e.g. "
        "imperative verbs, 'ignore', 'system', HTML-like tags such as "
        "<IMPORTANT>) intended to hijack the LLM's behavior when the output "
        "is fed back into its context."
    ),
    "over_scoped_oauth_credentials": (
        "An MCP server requests or is granted broader OAuth scopes or "
        "longer-lived tokens than needed for its function (e.g. full "
        "mailbox access instead of read-only), or shares credentials across "
        "servers."
    ),
    "supply_chain_compromise": (
        "An MCP server package is installed from an unverified source or "
        "public registry -- including a typosquatted package name -- "
        "without reviewing its source code or verifying its integrity."
    ),
    "sandbox_escape_local_server": (
        "A local MCP server runs with full host access (unrestricted file "
        "system or network access) instead of being sandboxed/isolated in a "
        "container or restricted environment."
    ),
    "message_tampering_or_replay": (
        "A JSON-RPC message between an MCP client and server is modified "
        "after TLS termination, or captured and resent, due to missing "
        "message-level signing, nonces, or timestamp-based replay "
        "protection."
    ),
    "missing_human_in_the_loop_approval": (
        "A sensitive, destructive, or financial MCP tool call is "
        "auto-approved, or approved without the full tool-call parameters "
        "being displayed to the user for explicit confirmation."
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
