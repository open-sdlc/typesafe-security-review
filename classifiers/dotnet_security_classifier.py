"""DotNet Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"DotNet Security Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python dotnet_security_classifier.py "some text to classify"
    python dotnet_security_classifier.py --file path/to/content.txt
    echo "some text" | python dotnet_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "DotNet Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "DotNet_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's OWASP Top 10-aligned sections:
# A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, and
# A05 Security Misconfiguration, as applied to the .NET Framework/ASP.NET.
CATEGORIES = {
    "weak_account_management": (
        "Cookies are missing the HttpOnly flag, session timeouts are overly "
        "long or use sliding expiration inappropriately, LogOn/Registration/"
        "password-reset endpoints lack brute-force throttling, or responses "
        "reveal whether an account exists (account enumeration)."
    ),
    "missing_function_level_authorization": (
        "A controller or action that should be restricted (e.g. an admin "
        "function) is missing an [Authorize] attribute/role check at the "
        "method or controller level, or authorization is rolled by hand "
        "instead of using the framework's built-in mechanisms."
    ),
    "insecure_direct_object_reference": (
        "A resource is looked up directly by a client-supplied ID (e.g. in "
        "an Edit/Details action) without verifying that the current user is "
        "actually authorized to access or modify that specific object."
    ),
    "weak_cryptography_practices": (
        "Custom/hand-rolled cryptographic functions are written, a weak "
        "hashing algorithm is used, password complexity requirements are "
        "insufficient, or a weak/obsolete encryption algorithm is used for "
        "data that needs confidentiality."
    ),
    "insufficient_transport_encryption": (
        "The application does not enforce TLS 1.2+ for the whole site, still "
        "allows obsolete SSL, or fails to redirect HTTP requests to HTTPS in "
        "production."
    ),
    "sql_injection": (
        "SQL is built via string concatenation with user input (dynamic SQL) "
        "and executed against the database, rather than using an ORM, stored "
        "procedures, or parameterized queries."
    ),
    "os_command_injection": (
        "User-controlled input is passed to a process-execution API (e.g. "
        "System.Diagnostics.Process.Start) or ProcessStartInfo.ArgumentList "
        "without allowlist validation, risking argument injection or command "
        "injection."
    ),
    "ldap_injection": (
        "User input is embedded into an LDAP distinguished name or filter "
        "without escaping special characters, risking LDAP injection against "
        "directory services such as Active Directory."
    ),
    "security_misconfiguration": (
        "Debug mode or stack traces are left enabled in production, default "
        "passwords are used, or the app fails to redirect HTTP to HTTPS via "
        "config transforms/middleware."
    ),
    "csrf_protection_gaps": (
        "A state-changing POST/PUT request is processed without validating "
        "an anti-forgery/CSRF token (missing @Html.AntiForgeryToken() or "
        "[ValidateAntiForgeryToken]), or tokens are not invalidated on "
        "logout."
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
