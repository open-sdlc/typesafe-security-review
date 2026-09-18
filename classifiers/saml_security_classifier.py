"""SAML Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"SAML Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python saml_security_classifier.py "some text to classify"
    python saml_security_classifier.py --file path/to/content.txt
    echo "some text" | python saml_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "SAML Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_transport_confidentiality": (
        "A SAML exchange is described as occurring without TLS 1.2+ or without "
        "digitally signed/encrypted assertions, exposing it to eavesdropping, "
        "message deletion, modification, or man-in-the-middle attacks."
    ),
    "incomplete_protocol_message_fields": (
        "A SAML AuthnRequest or Response is missing required data elements such "
        "as 'ID', 'InResponseTo', issuer, or service-provider identifiers -- the "
        "class of gap that made a real-world SSO implementation vulnerable to "
        "MITM."
    ),
    "xml_signature_wrapping": (
        "SAML XML processing skips schema validation, downloads schemas from a "
        "third party, or selects elements with 'getElementsByTagName'/relative "
        "XPath before signature validation, enabling an XML Signature Wrapping "
        "attack that lets an attacker forge an assertion's claimed identity."
    ),
    "weak_signature_or_key_selection": (
        "A relying party selects its signature verification algorithm from the "
        "untrusted JWT/SAML header itself, uses a MAC instead of a signature so "
        "multiple parties share trust of the same key, or otherwise mismanages "
        "which key/algorithm is used to validate an assertion."
    ),
    "replay_or_stolen_assertion": (
        "A SAML response/assertion lacks a short lifetime, 'OneTimeUse', or "
        "replay detection, or is cached in a way that lets a captured message be "
        "resent later to impersonate the original request."
    ),
    "unsolicited_idp_initiated_sso_risk": (
        "An IdP-initiated (unsolicited) SSO response is accepted without "
        "validating 'RelayState' against an allowlist, lacking the login-CSRF "
        "protection that SP-initiated flows have because there is no pre-login "
        "session to verify intent."
    ),
    "certificate_and_key_management_weakness": (
        "A SAML signing or encryption certificate/private key is poorly "
        "protected, reused across signing and encryption purposes, generated with "
        "a weak key size/algorithm, or trust in the IdP's certificate is pinned "
        "in a fragile, manual way."
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
