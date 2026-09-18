"""User Privacy Protection Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"User Privacy Protection Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python user_privacy_protection_classifier.py "some text to classify"
    python user_privacy_protection_classifier.py --file path/to/content.txt
    echo "some text" | python user_privacy_protection_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "User Privacy Protection Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "User_Privacy_Protection_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "Guidelines" section (strong
# cryptography, HSTS, certificate pinning, panic modes, remote session
# invalidation, anonymity networks, IP leakage, honesty/transparency). Each
# description is written so Jev (the TypeSafe model) can distinguish it from
# neighboring categories -- be specific about what does and does not count.
CATEGORIES = {
    "weak_data_protection_cryptography": (
        "User communications or stored private data (identities, secrets, credentials) are "
        "not protected with strong cryptography -- e.g. missing encryption in transit/"
        "storage, weak hashing of passwords, or insufficient key lengths."
    ),
    "missing_hsts_support": (
        "The platform does not implement HTTP Strict Transport Security (HSTS) to force "
        "user agents to only use secure HTTPS connections and reject untrusted TLS."
    ),
    "lack_of_certificate_pinning": (
        "The application does not pin expected certificates or public keys, leaving users "
        "exposed to interception if a Certificate Authority is compromised or a malicious "
        "root CA is trusted (e.g. in a corporate or national PKI environment)."
    ),
    "absence_of_panic_mode": (
        "The application offers no covert 'panic mode' capability that a threatened user "
        "could invoke to hide, delete, or protect sensitive data/accounts under duress."
    ),
    "no_remote_session_invalidation": (
        "Users have no way to view their currently active sessions or remotely invalidate/"
        "disconnect a session, such as one on a lost, stolen, or confiscated device."
    ),
    "anonymity_network_access_blocked": (
        "The service blocks or fails to support connections from anonymity networks such "
        "as Tor or I2P, removing an important protection avenue for users facing "
        "surveillance or censorship."
    ),
    "ip_address_leakage_via_embedded_content": (
        "Third-party or externally hosted content (avatars, images, embedded attachments) "
        "is loaded without an option to block it, allowing an adversary to learn a user's "
        "real IP address by hosting tracked content on their own domain."
    ),
    "lack_of_transparency_disclosure": (
        "The application fails to honestly inform users when their data is requested, "
        "logged, or subject to disclosure/investigation by external parties, preventing "
        "users from making an informed choice about using the service."
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
