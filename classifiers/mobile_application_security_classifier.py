"""Mobile Application Security Cheat Sheet classifier built on the TypeSafe
System One API.

Classifies input text against sub-categories drawn from the OWASP
"Mobile Application Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python mobile_application_security_classifier.py "some text to classify"
    python mobile_application_security_classifier.py --file path/to/content.txt
    echo "some text" | python mobile_application_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Mobile Application Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Mobile_Application_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "client_side_trust_violation": (
        "The app relies on client-side checks, spoofable device identifiers, "
        "or locally stored authentication/authorization decisions instead of "
        "enforcing authentication and authorization server-side."
    ),
    "insecure_credential_or_token_storage": (
        "Credentials, passwords, or authentication tokens are hardcoded, "
        "stored in plaintext, or kept outside a platform-provided secure "
        "storage mechanism such as Keychain (iOS) or Keystore (Android)."
    ),
    "weak_session_or_biometric_handling": (
        "Sessions do not time out or lack remote logout/randomly generated "
        "tokens, or biometric authentication is used without a secure "
        "fallback such as a PIN."
    ),
    "insecure_data_at_rest": (
        "Sensitive data is stored unencrypted on the device, placed in "
        "SharedPreferences/plist files, or cryptographic keys are not backed "
        "by hardware security features like Secure Enclave or StrongBox."
    ),
    "network_transport_weakness": (
        "The app disables or overrides TLS/SSL certificate validation, allows "
        "self-signed certificates, permits mixed SSL sessions, or sends "
        "sensitive data over an insecure channel such as SMS."
    ),
    "deep_link_or_shortcut_auth_bypass": (
        "A deep link, iOS Shortcut, Siri intent, or lock-screen widget can "
        "trigger a sensitive app action or reach a protected screen without "
        "requiring the device to be unlocked or the user re-authenticated."
    ),
    "insufficient_tamper_or_integrity_protection": (
        "The app lacks runtime anti-tampering controls such as detecting "
        "debugging/hooking/code injection, detecting rooted/jailbroken or "
        "emulated devices, verifying app signatures, or obfuscating the binary."
    ),
    "excessive_pii_collection_or_leakage": (
        "The app collects more personally identifiable information than "
        "necessary, or leaks sensitive data through caching, logging, or "
        "background app-switcher snapshots."
    ),
    "vulnerable_third_party_dependency": (
        "The app uses outdated, unvalidated, or unvetted third-party "
        "libraries/components, introducing supply-chain security risk."
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
