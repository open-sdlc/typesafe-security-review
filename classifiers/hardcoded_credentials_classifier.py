"""Use of Hard-coded Credentials classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the CWE (Common
Weakness Enumeration) entry for Use of Hard-coded Credentials and its closely
related weaknesses:
https://cwe.mitre.org/data/definitions/798.html
(see also CWE-259 Use of Hard-coded Password, CWE-321 Use of Hard-coded
Cryptographic Key, and CWE-1392 Use of Default Credentials)

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python hardcoded_credentials_classifier.py "some text to classify"
    python hardcoded_credentials_classifier.py --file path/to/content.txt
    echo "some text" | python hardcoded_credentials_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Use of Hard-coded Credentials (CWE-798)"
CHEATSHEET_URL = "https://cwe.mitre.org/data/definitions/798.html"

# Sub-categories drawn from CWE-798 (Use of Hard-coded Credentials) and its
# closely related weaknesses CWE-259 (Hard-coded Password), CWE-321
# (Hard-coded Cryptographic Key), and CWE-1392 (Use of Default Credentials).
# This promotes what is a single buried category elsewhere in this repo
# (secrets_management_classifier.py's hardcoded_plaintext_secret) into its own
# dedicated "secrets scanner"-style classifier, matching how dedicated tools
# such as gitleaks, trufflehog, and detect-secrets treat hardcoded-credential
# detection as an entire scanning category on its own. Each description is
# written so Jev (the TypeSafe model) can distinguish it from neighboring
# categories -- be specific about what does and does not count.
CATEGORIES = {
    "hardcoded_password_literal": (
        "A password is embedded directly in source code as a string literal "
        "constant, such as being compared against user-supplied input for "
        "authentication (e.g. `if (password == \"letmein123\")`), rather than "
        "being looked up from a secure credential store."
    ),
    "hardcoded_api_key_or_token": (
        "An API key, OAuth access token, client secret, or bearer token for "
        "a third-party or internal service is embedded directly as a literal "
        "value in source code, rather than being loaded from a secrets "
        "manager or injected at runtime."
    ),
    "hardcoded_connection_string_with_credentials": (
        "A database or service connection string embedded in source code "
        "contains an inline username and password (e.g. "
        "`postgres://user:pass@host/db` or a JDBC URL with credentials), "
        "rather than referencing credentials supplied out-of-band."
    ),
    "hardcoded_cryptographic_key_or_signing_secret": (
        "A cryptographic key, HMAC signing secret, JWT signing secret, or "
        "similar security-critical key material is embedded as a literal "
        "value directly in source code instead of being generated/stored "
        "separately, corresponding to CWE-321 (Use of Hard-coded "
        "Cryptographic Key)."
    ),
    "unchanged_default_vendor_credentials": (
        "A system, device, or application is deployed or documented using "
        "its default, factory-set, or vendor-supplied credentials (e.g. "
        "admin/admin, root/root, or a well-known default password) that were "
        "never changed after installation, corresponding to CWE-1392 (Use of "
        "Default Credentials)."
    ),
    "credentials_present_in_version_control_history": (
        "A credential (password, key, or token) was committed to a version "
        "control repository at some point and remains recoverable from the "
        "commit/change history, even if it has since been removed from the "
        "current working tree or the underlying secret has been rotated."
    ),
    "credentials_in_committed_config_file": (
        "A configuration, properties, or environment file (e.g. .env, "
        "config.yml, application.properties, web.config) containing "
        "plaintext credentials is checked into version control alongside "
        "application source code, rather than being excluded via "
        ".gitignore or an equivalent mechanism."
    ),
    "backdoor_or_debug_account_credential": (
        "A hidden backdoor account, debug-only login, or maintenance/support "
        "credential with a fixed, hard-coded value is left reachable in "
        "production code paths, allowing bypass of normal authentication."
    ),
    "hardcoded_credential_used_for_internal_service_auth": (
        "A hard-coded shared secret, API key, or password is used to "
        "authenticate one internal service, microservice, or component to "
        "another (service-to-service auth), embedded in code or a deployed "
        "container image rather than provisioned via a secrets management "
        "system."
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
