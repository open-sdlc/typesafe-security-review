"""OS Command Injection Defense Cheat Sheet classifier built on the TypeSafe
System One API.

Classifies input text against sub-categories drawn from the OWASP
"OS Command Injection Defense Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python os_command_injection_defense_classifier.py "some text to classify"
    python os_command_injection_defense_classifier.py --file path/to/content.txt
    echo "some text" | python os_command_injection_defense_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "OS Command Injection Defense Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "OS_Command_Injection_Defense_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's primary/additional defenses and
# argument-injection discussion. Each description is written so Jev (the
# TypeSafe model) can distinguish it from neighboring categories -- be
# specific about what does and does not count.
CATEGORIES = {
    "direct_os_command_invocation": (
        "The code builds and invokes an OS shell command (e.g. via "
        "`system()`, `exec()`, or backticks) using string concatenation of "
        "user input, instead of using an available built-in library function "
        "that accomplishes the same task without a shell."
    ),
    "missing_shell_metacharacter_escaping": (
        "User input is passed into a shell command without OS-specific "
        "escaping of shell metacharacters (such as `& | ; $ > < \\` ! ' \" ( "
        ")`), e.g. not using something like PHP's `escapeshellarg()`."
    ),
    "argument_injection": (
        "Attacker-controlled input that is meant to be a single value ends up "
        "injecting an additional command-line flag/argument into an "
        "otherwise fixed command (e.g. adding `--help` or another option), "
        "even though shell metacharacters were escaped."
    ),
    "unvalidated_command_allowlist": (
        "The actual command/executable name to run is taken from or "
        "influenced by user input without validating it against an "
        "allowlist of permitted commands."
    ),
    "unvalidated_command_arguments": (
        "Command arguments derived from user input are not validated against "
        "an allowlist or a restrictive regular expression (with metacharacters "
        "excluded and a bounded length), before being passed to the executed "
        "command."
    ),
    "excessive_process_privileges": (
        "The OS command or subprocess is executed with more privileges than "
        "the minimum required for the task, rather than under a low-privilege, "
        "isolated account limited to that single task."
    ),
    "shell_interpretation_ambiguity": (
        "The mechanism used to invoke the command passes the full string "
        "through a shell interpreter (like `/bin/sh`), allowing chaining "
        "metacharacters (`&`, `&&`, `|`, `||`) to run additional commands, as "
        "opposed to an API that splits command and arguments without "
        "invoking a shell."
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
