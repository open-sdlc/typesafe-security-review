"""Laravel Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Laravel Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python laravel_classifier.py "some text to classify"
    python laravel_classifier.py --file path/to/content.txt
    echo "some text" | python laravel_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Laravel Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Laravel_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "debug_mode_enabled_in_production": (
        "The Laravel APP_DEBUG environment variable is left set to true in "
        "a production deployment, risking exposure of stack traces and "
        "configuration details to end users."
    ),
    "insecure_session_cookie_config": (
        "Session/cookie configuration in config/session.php is missing "
        "HttpOnly, Secure, or a restrictive SameSite attribute, has an "
        "overly broad cookie domain, or the EncryptCookies middleware is "
        "disabled."
    ),
    "mass_assignment_vulnerability": (
        "A request is bound directly onto an Eloquent model using "
        "$request->all(), forceFill, or forceCreate (or the model is left "
        "unguarded / $guarded is empty), allowing an attacker to set fields "
        "like isAdmin that were never intended to be user-editable."
    ),
    "raw_sql_injection": (
        "A raw query expression (whereRaw, DB::raw, or similar) concatenates "
        "untrusted request input directly into the SQL string instead of "
        "using Laravel's SQL parameter bindings."
    ),
    "column_name_injection": (
        "User-supplied input is used directly as a column name or sort field "
        "(e.g. in where()/orderBy() or a Rule::unique() column argument) "
        "without validating it against an allow-list of legal column names."
    ),
    "blade_unescaped_output_xss": (
        "A Blade template renders untrusted user data using the unescaped "
        "{!! !!} syntax instead of the auto-escaping {{ }} syntax, risking "
        "reflected or stored Cross-Site Scripting."
    ),
    "unrestricted_file_upload": (
        "An uploaded file's type/MIME and size are not validated, or a "
        "user-supplied filename is used to determine the storage path "
        "without stripping directory information, risking storage abuse or "
        "remote code execution."
    ),
    "path_traversal_download": (
        "A file path used for reading/downloading a file (e.g. via "
        "response()->download()) incorporates a user-supplied filename "
        "without stripping '../' traversal sequences."
    ),
    "open_redirect": (
        "The application redirects the user to a URL taken directly from "
        "request input (e.g. redirect($request->input('url'))) without "
        "validating it against an allow-list of permitted destinations."
    ),
    "missing_csrf_protection": (
        "A state-changing POST/PUT/DELETE route is missing Laravel's "
        "VerifyCsrfToken middleware or a valid CSRF token, or is improperly "
        "added to the CSRF-exempt $except list despite not being stateless."
    ),
    "command_injection": (
        "Untrusted request input is passed unescaped into a shell command "
        "(e.g. via PHP's exec()) instead of being sanitized with "
        "escapeshellarg/escapeshellcmd."
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
