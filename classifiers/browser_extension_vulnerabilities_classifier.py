"""Browser Extension Vulnerabilities Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Browser Extension Vulnerabilities Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python browser_extension_vulnerabilities_classifier.py "some text to classify"
    python browser_extension_vulnerabilities_classifier.py --file path/to/content.txt
    echo "some text" | python browser_extension_vulnerabilities_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Browser Extension Vulnerabilities Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Browser_Extension_Vulnerabilities_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "permissions_overreach": (
        "A browser extension's manifest requests broader permissions than "
        "functionally necessary -- e.g. access to all tabs, all URLs, or full "
        "browsing history -- instead of following least privilege and "
        "optional/scoped permissions."
    ),
    "data_leakage_to_external_server": (
        "An extension transmits browsing activity, tab URLs, or personal data to "
        "an external server without the user's knowledge, consent, or a privacy "
        "policy disclosure."
    ),
    "extension_dom_xss": (
        "User input is inserted into an extension's page or a web page's DOM via "
        "innerHTML without sanitization, allowing injected script execution."
    ),
    "insecure_http_communication": (
        "An extension communicates with a server over plain HTTP instead of "
        "HTTPS, exposing transmitted data to interception or tampering."
    ),
    "dynamic_remote_code_injection": (
        "An extension dynamically loads and executes a script from a remote or "
        "untrusted source (e.g. injecting a <script> tag or eval-ing fetched "
        "code) instead of shipping fixed, reviewed code."
    ),
    "malicious_update_channel": (
        "An extension fetches or executes 'update' code from an untrusted server "
        "or without digital-signature/integrity verification, instead of relying "
        "solely on the official extension marketplace update mechanism."
    ),
    "vulnerable_third_party_dependency": (
        "An extension bundles an outdated or known-vulnerable third-party library "
        "or dependency that has not been audited or updated."
    ),
    "missing_or_weak_csp": (
        "An extension lacks a strict Content Security Policy (or defines an "
        "overly permissive one), allowing inline or injected scripts to execute "
        "in its pages."
    ),
    "insecure_local_storage_of_secrets": (
        "An extension stores sensitive data such as authentication tokens or API "
        "keys in localStorage or hardcoded in source instead of using an "
        "encrypted, extension-specific storage API."
    ),
    "dom_based_data_skimming": (
        "An extension renders sensitive user data (PII, financial details, chat "
        "history) directly into a web page's DOM, making it readable by the "
        "page's own (potentially malicious) scripts."
    ),
    "prototype_pollution_data_skimming": (
        "An extension executes a script in the web page's main-world JavaScript "
        "context while handling sensitive data, allowing a malicious page that "
        "has overwritten global object/prototype setters to exfiltrate that data."
    ),
    "insecure_message_passing": (
        "An extension's privileged background/service-worker script accepts "
        "chrome.runtime.sendMessage calls without validating the sender's ID, "
        "URL, or origin, letting a compromised web page or content script trigger "
        "privileged actions."
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
