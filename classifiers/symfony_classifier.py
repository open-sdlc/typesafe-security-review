"""Symfony Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Symfony Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Symfony_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python symfony_classifier.py "some text to classify"
    python symfony_classifier.py --file path/to/content.txt
    echo "some text" | python symfony_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Symfony Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Symfony_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "Main Sections" (XSS, CSRF, SQL
# injection, command injection, open redirection, file upload, directory
# traversal, dependencies, CORS). Each description is written so Jev (the
# TypeSafe model) can distinguish it from neighboring categories -- be
# specific about what does and does not count.
CATEGORIES = {
    "twig_output_escaping_bypass": (
        "User-controlled data is rendered using Twig's raw filter or with output escaping "
        "otherwise disabled, allowing injected script such as <script> tags to execute "
        "(Cross-Site Scripting) instead of being HTML-escaped by default."
    ),
    "missing_or_invalid_csrf_token": (
        "A state-changing form or request lacks Symfony's CSRF token protection (disabled "
        "csrf_protection, missing security/csrf component, or no server-side validation via "
        "isCsrfTokenValid()), allowing Cross-Site Request Forgery."
    ),
    "doctrine_dql_injection": (
        "A Doctrine DQL or raw SQL query is built via direct string concatenation of "
        "user input rather than bound parameters or the entity repository API, enabling "
        "SQL Injection."
    ),
    "os_command_injection": (
        "User-supplied input is passed unsanitized into a shell-executing function such as "
        "exec(), allowing an attacker to append or inject additional OS commands (e.g. "
        "'; rm -rf .')."
    ),
    "open_redirection": (
        "A controller redirects the user to a URL taken directly from an unvalidated "
        "request parameter (e.g. $this->redirect($url)), allowing attackers to redirect "
        "victims to an arbitrary malicious site."
    ),
    "insecure_file_upload": (
        "Uploaded files are accepted without server-side validation of file type/size, "
        "without unique filenames to prevent overwrites, or are stored inside the publicly "
        "served directory instead of outside it."
    ),
    "directory_path_traversal": (
        "A filename or path parameter from user input is used to build a filesystem path "
        "without validating the resolved absolute path or stripping directory components "
        "(e.g. via basename/realpath), allowing access outside the intended storage "
        "directory using '../' sequences."
    ),
    "outdated_vulnerable_dependencies": (
        "Symfony components or third-party Composer packages are outdated or contain known "
        "vulnerabilities that have not been checked via a dependency/security-checker tool."
    ),
    "cors_misconfiguration": (
        "Cross-Origin Resource Sharing is configured too permissively (e.g. via nelmio/"
        "cors-bundle) allowing untrusted origins to interact with routes/resources that "
        "should be restricted."
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
