"""Java Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Java Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python java_security_classifier.py "some text to classify"
    python java_security_classifier.py --file path/to/content.txt
    echo "some text" | python java_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Java Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Java_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "untrusted_input_to_interpreter": (
        "Untrusted input is passed into an interpreter-style API (a SQL "
        "query, JPA/JPQL query, XPath expression, OS command, or NoSQL API "
        "call) built via string concatenation instead of a parameterized or "
        "API-based construction method."
    ),
    "output_encoding_missing": (
        "User-controlled data is written into an HTTP response without both "
        "strict allow-list input validation and HTML sanitizing/encoding "
        "(e.g. OWASP Java HTML Sanitizer or Java Encoder) before being sent "
        "to the browser."
    ),
    "log_forging_via_unstructured_logs": (
        "Untrusted data is concatenated directly into an unstructured log "
        "message rather than passed via parameterized logging calls (e.g. "
        "SLF4J/Log4j '{}' placeholders) or a structured JSON log layout, "
        "enabling CRLF-based log injection/forging."
    ),
    "custom_cryptography_implementation": (
        "Content describes writing or designing a custom/home-grown "
        "cryptographic algorithm, protocol, or encoding scheme instead of "
        "using a vetted, well-known cryptography library."
    ),
    "improper_jca_jce_direct_use": (
        "Cryptography is implemented by directly using Java's built-in JCA/"
        "JCE classes (Cipher, KeyGenerator, etc.) instead of a higher-level "
        "vetted library (e.g. Google Tink), without an expert review of the "
        "resulting design."
    ),
    "nonce_or_iv_reuse": (
        "A nonce or initialization vector is reused or improperly managed "
        "across multiple encryption operations performed with the same key "
        "(e.g. repeated AES-GCM encryption), which can break confidentiality "
        "guarantees."
    ),
    "missing_key_rotation": (
        "Cryptographic sample code or design does not account for key "
        "rotation or key management, relying on a single long-lived key "
        "without any rotation strategy."
    ),
    "unverified_public_key_exchange": (
        "Public keys are exchanged for asymmetric or hybrid encryption "
        "(e.g. between two parties establishing a shared secret) without "
        "validating the authenticity of the received public key, risking "
        "impersonation or a man-in-the-middle attack."
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
