"""TLS Cipher String Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"TLS Cipher String Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html

# NOTE: The live page has been deprecated by OWASP and simply redirects to the
# "Transport Layer Security Cheat Sheet" (see Transport_Layer_Security_Cheat_Sheet.html).
# No cipher-string-specific body content could be fetched from the URL above, so the
# categories below were derived from OWASP/security domain knowledge of TLS cipher
# suite selection (the historical, narrower scope of this specific cheat sheet), cross
# checked against the cipher-suite guidance now hosted on the Transport Layer Security
# Cheat Sheet page.

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python tls_cipher_string_classifier.py "some text to classify"
    python tls_cipher_string_classifier.py --file path/to/content.txt
    echo "some text" | python tls_cipher_string_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "TLS Cipher String Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "TLS_Cipher_String_Cheat_Sheet.html"
)

# Sub-categories focused specifically on cipher suite / cipher string
# selection risks (as opposed to the broader TLS deployment concerns covered
# by the Transport Layer Security cheat sheet). Each description is written
# so Jev (the TypeSafe model) can distinguish it from neighboring categories
# -- be specific about what does and does not count.
CATEGORIES = {
    "weak_protocol_version_enabled": (
        "The server or client configuration allows legacy protocol versions such as SSLv2, "
        "SSLv3, TLS 1.0, or TLS 1.1 instead of restricting to TLS 1.2/1.3 only."
    ),
    "null_or_anonymous_cipher_enabled": (
        "The cipher configuration permits NULL ciphers (no encryption) or anonymous "
        "ciphers (TLS_*_anon_*, no authentication), which provide no real confidentiality "
        "or identity guarantees."
    ),
    "export_grade_cipher_enabled": (
        "The cipher configuration permits deliberately weakened EXPORT-grade ciphers "
        "(TLS_*_EXPORT_*) historically required for export-control compliance."
    ),
    "non_forward_secret_key_exchange": (
        "The cipher suite uses static RSA key transport or non-ephemeral (static) "
        "Diffie-Hellman for key exchange (TLS_RSA_*, TLS_DH_*) instead of an ephemeral "
        "exchange, so a compromised private key can decrypt previously captured traffic."
    ),
    "cbc_mode_cipher_risk": (
        "A CBC-mode cipher suite is used instead of an AEAD suite (AES-GCM or "
        "ChaCha20-Poly1305), leaving the connection potentially exposed to padding-oracle "
        "style attacks such as BEAST or Lucky13."
    ),
    "weak_diffie_hellman_parameters": (
        "The negotiated or configured Diffie-Hellman group/parameters are weak, small, or "
        "improperly generated, rather than using a modern, sufficiently large standardized "
        "group such as those in RFC 7919."
    ),
    "missing_downgrade_protection": (
        "The server does not enable the TLS_FALLBACK_SCSV signaling cipher suite value, "
        "leaving the connection susceptible to a forced protocol downgrade attack."
    ),
    "insecure_cipher_preference_order": (
        "The server does not enforce its own preferred cipher order (or has none "
        "configured), allowing a client -- potentially a malicious one -- to steer "
        "negotiation toward the weakest mutually supported cipher."
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
