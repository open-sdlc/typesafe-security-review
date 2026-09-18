"""Transport Layer Protection Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Transport Layer Protection Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html

# NOTE: The live page has been deprecated by OWASP and simply redirects to the
# "Transport Layer Security Cheat Sheet" (see Transport_Layer_Security_Cheat_Sheet.html).
# No body content specific to this older page name could be fetched from the URL above, so
# the categories below were derived from OWASP/security domain knowledge of this cheat
# sheet's historical, broader "when/where must transport security be applied" scope (e.g.
# mixed content, certificate trust, HSTS), kept distinct from the narrower cipher-suite
# scope of the TLS Cipher String cheat sheet and the comprehensive scope of the current
# Transport Layer Security cheat sheet.

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python transport_layer_protection_classifier.py "some text to classify"
    python transport_layer_protection_classifier.py --file path/to/content.txt
    echo "some text" | python transport_layer_protection_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Transport Layer Protection Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Transport_Layer_Protection_Cheat_Sheet.html"
)

# Sub-categories focused on when and where transport-layer protection must be
# applied across an application (as opposed to cipher-suite selection or deep
# TLS server/certificate configuration). Each description is written so Jev
# (the TypeSafe model) can distinguish it from neighboring categories -- be
# specific about what does and does not count.
CATEGORIES = {
    "sensitive_traffic_over_plain_http": (
        "Login pages, session cookies, or other sensitive data are transmitted over an "
        "unencrypted HTTP connection instead of being protected end-to-end by TLS."
    ),
    "mixed_content_on_page": (
        "A page served over HTTPS also loads some resources (images, scripts, CSS) over "
        "plain HTTP, or a single host serves both encrypted and unencrypted content, "
        "undermining the page's overall transport security."
    ),
    "improper_certificate_trust_validation": (
        "A client or application accepts an expired, self-signed, revoked, or hostname-"
        "mismatched TLS certificate without warning or rejection, instead of properly "
        "validating the certificate chain."
    ),
    "protocol_downgrade_to_http": (
        "A user session or request is allowed to fall back from HTTPS to HTTP, or the "
        "application does not consistently enforce HTTPS across the full user session."
    ),
    "missing_hsts_enforcement": (
        "The application does not send an HTTP Strict Transport Security (HSTS) header, "
        "leaving users vulnerable to protocol-downgrade or SSL-stripping style attacks on "
        "their first/insecure connection."
    ),
    "unencrypted_internal_service_traffic": (
        "Backend-to-backend or internal service-to-service traffic is transmitted without "
        "TLS protection, based on an assumption that internal networks are inherently "
        "trusted."
    ),
    "weak_certificate_key_or_hash": (
        "A TLS certificate uses an insufficiently strong private key size or a weak "
        "signing hash algorithm (such as MD5 or SHA-1) instead of current best-practice key "
        "lengths and SHA-256 or stronger."
    ),
    "session_cookie_missing_secure_flag": (
        "A cookie carrying session or authentication data is set without the 'Secure' "
        "attribute, allowing it to be transmitted over a non-HTTPS channel even on a "
        "TLS-enabled site."
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
