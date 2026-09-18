"""Path Traversal (CWE-22) classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the CWE (Common
Weakness Enumeration) entries for path/directory traversal, rooted in:
https://cwe.mitre.org/data/definitions/22.html

This module closes a gap not covered by the OWASP Cheat Sheet Series: it
grounds its categories directly in CWE-22 (Path Traversal) and its closely
related children/siblings -- CWE-23 (Relative Path Traversal), CWE-36
(Absolute Path Traversal), CWE-41 (Improper Resolution of Path Equivalence),
CWE-59 (Improper Link Resolution Before File Access), CWE-66 (Improper
Handling of File Names that Identify Virtual Resources), and CWE-73
(External Control of File Name or Path) -- plus well-known real-world
variants such as "zip-slip" archive extraction, null-byte path truncation,
and Local File Inclusion (LFI).

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python path_traversal_classifier.py "some text to classify"
    python path_traversal_classifier.py --file path/to/content.txt
    echo "some text" | python path_traversal_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Path Traversal (CWE-22)"
CHEATSHEET_URL = "https://cwe.mitre.org/data/definitions/22.html"

# Sub-categories drawn from CWE-22 and its closely related CWE entries. Each
# description is written so Jev (the TypeSafe model) can distinguish it from
# neighboring categories -- be specific about what does and does not count.
CATEGORIES = {
    "dot_dot_slash_relative_traversal": (
        "User-controlled input containing relative traversal sequences such "
        "as '../' or '..\\' is concatenated into a file system path without "
        "sanitization, allowing an attacker to escape the intended base "
        "directory and reach arbitrary files elsewhere on disk (CWE-23)."
    ),
    "absolute_path_injection": (
        "User-controlled input is allowed to supply a fully-qualified "
        "absolute path (e.g. '/etc/passwd' or 'C:\\Windows\\...') that "
        "overrides an intended base directory, instead of being restricted "
        "to a relative path within a sandboxed root (CWE-36)."
    ),
    "path_equivalence_encoding_bypass": (
        "A path traversal or file-access filter is bypassed using an "
        "alternate but equivalent representation of the same path, such as "
        "double URL-encoding ('%252e%252e%252f'), Unicode/overlong UTF-8 "
        "encoding, mixed slash/backslash separators, or trailing dots/spaces "
        "that Windows silently strips, causing the check and the actual "
        "resolved path to disagree (CWE-41)."
    ),
    "symlink_following_race": (
        "A file or directory operation follows a symbolic link without "
        "verifying it does not point outside the intended directory, or a "
        "TOCTOU race lets an attacker swap a symlink between a validation "
        "check and the actual file open/access, redirecting the operation "
        "to an unintended target (CWE-59)."
    ),
    "zip_slip_archive_extraction": (
        "An archive (zip/tar/jar/rar) is extracted using entry names taken "
        "directly from the archive without validating that each resulting "
        "path stays within the target extraction directory, letting a "
        "malicious archive entry named e.g. '../../etc/cron.d/evil' write "
        "files outside the intended folder (the 'zip-slip' pattern)."
    ),
    "null_byte_or_legacy_truncation_bypass": (
        "A file path validation or extension check is bypassed by appending "
        "a null byte ('\\0') or other legacy string-truncation trick to "
        "user input, causing a lower-level file API to stop reading the "
        "path before a validated suffix (e.g. 'file.php%00.jpg')."
    ),
    "insufficient_canonicalization_before_validation": (
        "A path is validated (e.g. checked against an allowlist or for "
        "traversal sequences) before being canonicalized/resolved, or is "
        "canonicalized and then re-validated inconsistently, so the "
        "resolved real path used for the actual file operation differs from "
        "the one that was checked (validate-then-resolve TOCTOU)."
    ),
    "local_file_inclusion_via_untrusted_path": (
        "Untrusted input is passed directly into a dynamic include, "
        "require, import, or template-rendering call (e.g. PHP 'include', "
        "server-side template engines, or dynamic module loaders) so that "
        "an attacker-controlled path causes arbitrary local file content to "
        "be executed or rendered (Local File Inclusion / LFI)."
    ),
    "external_control_of_file_name_or_path": (
        "A file name or path component used in a sensitive file system "
        "operation is derived directly from external/attacker-controlled "
        "input (query parameters, headers, form fields) without being "
        "restricted to a safe, pre-approved set of values (CWE-73)."
    ),
    "improper_handling_of_virtual_resource_names": (
        "Special or reserved file names that identify virtual resources "
        "(such as Windows device names like 'CON', 'AUX', 'NUL', "
        "'/dev/null', '/proc/self/', or UNC paths) are not specifically "
        "rejected or handled, letting an attacker reference a virtual "
        "resource where a normal file was expected (CWE-66)."
    ),
    "missing_chroot_or_sandbox_confinement": (
        "File operations driven by user input are performed without any "
        "operating-system-level confinement (chroot jail, container "
        "filesystem isolation, restricted service account, or an "
        "allowlisted base-directory sandbox) that would limit the blast "
        "radius of a successful path traversal even if application-level "
        "checks fail."
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
