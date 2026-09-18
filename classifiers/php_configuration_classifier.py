"""PHP Configuration Cheat Sheet classifier built on the TypeSafe System One
API.

Classifies input text against sub-categories drawn from the OWASP
"PHP Configuration Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python php_configuration_classifier.py "some text to classify"
    python php_configuration_classifier.py --file path/to/content.txt
    echo "some text" | python php_configuration_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "PHP Configuration Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "PHP_Configuration_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's php.ini directive groupings
# (error handling, general settings, file uploads, executable handling,
# session handling). Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "verbose_error_disclosure": (
        "PHP is configured with `display_errors`/`display_startup_errors` on "
        "or `expose_php` on in a production-facing environment, leaking stack "
        "traces, file paths, or the PHP version to users/attackers."
    ),
    "unsafe_remote_file_wrapper_config": (
        "`allow_url_fopen` or `allow_url_include` is enabled, which can "
        "escalate a Local File Inclusion (LFI) vulnerability into a Remote "
        "File Inclusion (RFI) allowing execution of attacker-hosted code."
    ),
    "dangerous_functions_enabled": (
        "Dangerous PHP functions such as `exec`, `system`, `shell_exec`, "
        "`passthru`, `popen`, `proc_open`, or `phpinfo` are left callable "
        "instead of being disabled via the `disable_functions` directive."
    ),
    "insecure_session_cookie_config": (
        "Session cookie settings omit `secure`, `httponly`, or `samesite` "
        "protections, use a short/weak session ID length, or keep the "
        "default session cookie name, weakening session hijacking defenses."
    ),
    "unrestricted_file_upload_config": (
        "File uploads (`file_uploads`) are left enabled, or "
        "`upload_max_filesize`/`max_file_uploads` are not restricted, even "
        "when the application does not need file upload functionality."
    ),
    "missing_open_basedir_restriction": (
        "`doc_root` and `open_basedir` are not configured to restrict PHP "
        "script file access to the intended application directory, allowing "
        "scripts to read or write files elsewhere on the filesystem."
    ),
    "outdated_unsupported_php_version": (
        "The application runs on a PHP branch that is no longer on the "
        "officially supported versions list, missing upstream security "
        "patches."
    ),
    "missing_resource_limits": (
        "`memory_limit`, `post_max_size`, or `max_execution_time` are not "
        "bounded, allowing a single request to exhaust server resources and "
        "cause a denial of service."
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
