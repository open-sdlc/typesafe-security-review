"""Transport Layer Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Transport Layer Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python transport_layer_security_classifier.py "some text to classify"
    python transport_layer_security_classifier.py --file path/to/content.txt
    echo "some text" | python transport_layer_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Transport Layer Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Transport_Layer_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "Server Configuration" and
# "Certificates" sections (protocols, ciphers, DH groups, compression,
# libraries, key strength, domain names, wildcards, CAs, CAA, validation
# type). Each description is written so Jev (the TypeSafe model) can
# distinguish it from neighboring categories -- be specific about what does
# and does not count.
CATEGORIES = {
    "deprecated_protocol_version_supported": (
        "The server or client allows deprecated protocol versions -- SSLv2, SSLv3, TLS "
        "1.0, or TLS 1.1 -- rather than defaulting to TLS 1.3 and, at most, supporting "
        "TLS 1.2 for compatibility."
    ),
    "weak_cipher_suite_configuration": (
        "The cipher configuration includes null, anonymous, EXPORT-grade, static RSA "
        "transport, or non-forward-secret Diffie-Hellman cipher suites instead of modern "
        "AEAD suites (AES-GCM or ChaCha20-Poly1305)."
    ),
    "weak_diffie_hellman_group": (
        "The negotiated Diffie-Hellman or elliptic-curve group is weak, undersized, or "
        "improperly/randomly generated, instead of using a standardized modern group (e.g. "
        "ffdhe2048+, x25519, secp384r1, or a post-quantum hybrid like X25519MLKEM768)."
    ),
    "tls_compression_enabled": (
        "TLS-level compression is enabled on the server, exposing the connection to the "
        "CRIME attack, which can recover sensitive data such as session cookies via "
        "compression-ratio side channels."
    ),
    "outdated_or_vulnerable_tls_library": (
        "The server or client uses an outdated cryptographic/TLS library with known "
        "vulnerabilities (e.g. an unpatched Heartbleed-class flaw) instead of being kept "
        "current with security patches."
    ),
    "weak_private_key_or_certificate_hash": (
        "A certificate's private key is undersized (e.g. RSA key below 2048 bits) or the "
        "certificate is signed using a weak hashing algorithm such as MD5 or SHA-1 instead "
        "of SHA-256 or stronger."
    ),
    "certificate_domain_name_mismatch": (
        "The certificate's CN/subjectAlternativeName does not correctly match the fully "
        "qualified domain name being served, or the certificate improperly includes "
        "internal-only hostnames or IP addresses on an externally facing cert."
    ),
    "risky_wildcard_certificate_sharing": (
        "A wildcard certificate (e.g. *.example.org) is shared across systems at different "
        "trust levels, such as between a public web server and an internal server or VPN "
        "gateway, increasing the impact of a single private-key compromise."
    ),
    "untrusted_or_unrestricted_ca_issuance": (
        "A certificate is issued by a CA not restricted via a CAA DNS record, or a public-"
        "facing service uses a certificate from an internal/private CA that is not trusted "
        "by external users' browsers."
    ),
    "missing_downgrade_attack_protection": (
        "The server does not enable the TLS_FALLBACK_SCSV signaling mechanism, leaving "
        "connections open to a forced protocol-downgrade attack that pushes the client to a "
        "weaker, deprecated TLS/SSL version."
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
