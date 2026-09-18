"""Ruby on Rails Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Ruby on Rails Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python ruby_on_rails_classifier.py "some text to classify"
    python ruby_on_rails_classifier.py --file path/to/content.txt
    echo "some text" | python ruby_on_rails_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Ruby on Rails Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Ruby_on_Rails_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "ruby_command_injection": (
        "User-influenced input reaches a Ruby command-execution primitive such as "
        "eval, system, backticks, exec, spawn, IO.popen, or Process.spawn, "
        "letting an attacker run arbitrary OS commands or Ruby code."
    ),
    "activerecord_sql_injection": (
        "A Rails/ActiveRecord query is built by string-interpolating user input "
        "directly into a 'where' clause (e.g. 'name like ' + name + '') instead "
        "of using '?' placeholders or sanitize_sql_like."
    ),
    "unsafe_html_output_xss": (
        "View code uses 'raw', 'html_safe', or '<%== %>' on a value derived from "
        "user input, bypassing Rails' default HTML escaping and creating a "
        "reflected or stored XSS sink."
    ),
    "javascript_uri_link_xss": (
        "A 'link_to' href value is built from user-controlled data that can "
        "contain a 'javascript:' URI, causing script execution when the generated "
        "link is clicked."
    ),
    "insecure_cookie_session_store": (
        "The application relies on Rails' default cookie-based session store for "
        "sensitive data or long-lived sessions without switching to a server-side "
        "(e.g. database-backed) session store, risking replay of stale sessions."
    ),
    "idor_forceful_browsing": (
        "A predictable, RESTful resource URL (e.g. '/projects/42') is accessed or "
        "modified without a per-object authorization check (cancancan/pundit- "
        "style), allowing access to another user's data by guessing IDs."
    ),
    "csrf_protection_gap": (
        "A Rails controller lacks 'protect_from_forgery', excepts a state- "
        "changing action from it, or a form performs a state change via GET, "
        "leaving the action vulnerable to cross-site request forgery."
    ),
    "open_redirect_vulnerability": (
        "A 'redirect_to' call uses a raw user-supplied 'url' parameter without "
        "validating it against an allowlist of hosts/paths, letting an attacker "
        "redirect victims to an arbitrary external site."
    ),
    "dynamic_render_path_injection": (
        "User input is used to choose which view, partial, or template a "
        "controller's 'render' call loads, potentially exposing an unintended "
        "(e.g. administrative) view."
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
