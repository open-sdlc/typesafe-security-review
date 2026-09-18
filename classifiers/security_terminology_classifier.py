"""Security Terminology Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Security Terminology Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Security_Terminology_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python security_terminology_classifier.py "some text to classify"
    python security_terminology_classifier.py --file path/to/content.txt
    echo "some text" | python security_terminology_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Security Terminology Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Security_Terminology_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "encoding_treated_as_security_control": (
        "Text treats reversible data encoding (Base64, URL encoding, HTML entity "
        "encoding) as if it were itself a security/confidentiality control, "
        "rather than a data-usability transformation with no inherent security "
        "value."
    ),
    "escaping_vs_sanitization_confusion": (
        "Text conflates escaping (prefixing control characters so a parser treats "
        "them as literal text, e.g. preventing XSS/SQLi) with sanitization "
        "(removing/filtering dangerous content), or treats sanitization as a "
        "sufficient primary defense instead of a secondary one."
    ),
    "insecure_deserialization_object_reconstruction": (
        "Text describes reconstructing an object or data structure from untrusted "
        "serialized data without validation, the scenario in which insecure "
        "deserialization can lead to remote code execution."
    ),
    "encryption_hashing_signature_mismatch": (
        "Text uses the wrong cryptographic primitive for the stated goal -- e.g. "
        "'encrypting' a password for storage instead of hashing it, or claiming "
        "confidentiality (encryption) when integrity/authenticity "
        "(hashing/signatures) is what's actually needed."
    ),
    "missing_digital_signature_for_authenticity": (
        "Text needs to prove who sent a message and that it was not altered "
        "(authenticity and non-repudiation) but describes a mechanism without a "
        "proper digital signature scheme (sign with private key, verify with "
        "public key)."
    ),
    "authentication_authorization_conflation": (
        "Text treats successfully verifying identity (authentication -- 'who are "
        "you?') as automatically granting permission to perform an action "
        "(authorization -- 'are you allowed to do this?'), conflating the two "
        "distinct security decisions."
    ),
    "federated_identity_role_confusion": (
        "Text mixes up the distinct roles in a federated identity flow -- "
        "Identity Provider (authenticates), Relying Party/Service Provider "
        "(relies on the IdP), and Principal (the entity being authenticated) -- "
        "in a way that misattributes which party performs which function."
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
