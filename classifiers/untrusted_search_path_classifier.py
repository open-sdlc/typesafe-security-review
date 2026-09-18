"""Untrusted Search Path (CWE-426) classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the CWE (Common
Weakness Enumeration) entry for Untrusted Search Path:
https://cwe.mitre.org/data/definitions/426.html

This covers untrusted/uncontrolled search-path weaknesses, primarily
relevant to native applications, installers, and services -- the Windows
DLL-hijacking family and Unix/Linux equivalents. Categories are grounded in
CWE-426 (Untrusted Search Path), CWE-427 (Uncontrolled Search Path Element),
and CWE-428 (Unquoted Search Path or Element).

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python untrusted_search_path_classifier.py "some text to classify"
    python untrusted_search_path_classifier.py --file path/to/content.txt
    echo "some text" | python untrusted_search_path_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Untrusted Search Path (CWE-426)"
CHEATSHEET_URL = "https://cwe.mitre.org/data/definitions/426.html"

# Sub-categories drawn from CWE-426, CWE-427, and CWE-428. Each description
# is written so Jev (the TypeSafe model) can distinguish it from neighboring
# categories -- be specific about what does and does not count.
CATEGORIES = {
    "dll_hijacking_via_working_directory_search_order": (
        "A Windows application loads a DLL/shared library by name and the "
        "current working directory (or the application's own directory) is "
        "searched before trusted system directories, allowing an attacker "
        "to plant a malicious DLL with a matching name that gets loaded "
        "instead of the legitimate system library."
    ),
    "unquoted_service_path_with_spaces": (
        "A Windows service, scheduled task, or registry Run key specifies "
        "an executable path containing spaces without surrounding quotes "
        "(e.g. `C:\\Program Files\\App\\app.exe`), letting an attacker who "
        "can write to an intermediate directory place a malicious "
        "executable (e.g. `C:\\Program.exe`) that gets executed first due "
        "to how Windows resolves the unquoted, space-delimited path "
        "(CWE-428)."
    ),
    "untrusted_environment_variable_influencing_search_path": (
        "A search-path-style environment variable (`PATH`, "
        "`LD_LIBRARY_PATH`, `PYTHONPATH`, `NODE_PATH`, or similar) can be "
        "set or influenced by an untrusted or lower-privileged user/process "
        "before a higher-privileged process runs and consults that "
        "variable to locate executables or libraries."
    ),
    "loading_from_world_writable_or_user_writable_directory": (
        "A library, module, plugin, or executable is dynamically loaded "
        "from a directory that is world-writable or writable by "
        "lower-privileged users, allowing an attacker to substitute a "
        "malicious file that a privileged process will then load and "
        "execute."
    ),
    "invoking_executable_by_relative_or_bare_name": (
        "Code (a script, build step, service, or scheduled task) invokes an "
        "executable using a bare or relative name (e.g. just `gcc`, "
        "`.\\tool.exe`, or `./helper`) instead of a fully-qualified absolute "
        "path, relying on whatever search path is in effect at execution "
        "time rather than pinning the exact trusted binary location "
        "(CWE-427)."
    ),
    "untrusted_plugin_or_module_directory_search_without_validation": (
        "A plugin, module, or extension loader searches multiple "
        "directories in sequence for a matching file name and loads the "
        "first match found, without validating the trustworthiness, "
        "signature, or ownership of the directory or file before loading "
        "it."
    ),
    "installer_or_build_script_prepending_untrusted_directory_to_path": (
        "An installer, build script, or CI/CD pipeline step adds a "
        "temporary, user-controlled, or otherwise untrusted directory to "
        "the front of a search-path environment variable, causing "
        "subsequent commands in that session or process tree to "
        "preferentially resolve from the untrusted directory."
    ),
    "missing_fully_qualified_path_validation_at_privileged_load_time": (
        "A privileged process (running as root/SYSTEM or with elevated "
        "rights) resolves an executable, library, or configuration file via "
        "search-path lookup at startup or runtime instead of requiring and "
        "validating a fully-qualified, access-controlled path, creating a "
        "privilege-escalation opportunity if any searched location is "
        "attacker-influenced."
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
