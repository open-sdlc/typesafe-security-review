"""JSON Web Token Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"JSON Web Token Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python json_web_token_classifier.py "some text to classify"
    python json_web_token_classifier.py --file path/to/content.txt
    echo "some text" | python json_web_token_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "JSON Web Token Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "JSON_Web_Token_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "alg_none_acceptance": (
        "A JWT verifier accepts an unsecured token declaring \"alg\":\"none\", "
        "letting an attacker forge a token that carries no valid cryptographic "
        "signature at all."
    ),
    "key_type_confusion": (
        "A public key intended for asymmetric digital-signature verification "
        "(e.g. RS256/ES256) is instead misused as a symmetric MAC secret (e.g. "
        "HS256) or vice versa, letting an attacker forge tokens using the "
        "known public key as the HMAC secret."
    ),
    "untrusted_key_source_header": (
        "The verification key or its location is taken from an unauthenticated "
        "JOSE header parameter (jwk, jku, x5u, or kid) without anchoring it to "
        "an out-of-band trusted root, risking acceptance of an attacker-"
        "supplied key or SSRF when the key is fetched by URL."
    ),
    "weak_or_reused_secret": (
        "An HMAC secret used to sign/verify JWTs is too short, guessable or "
        "password-derived, hardcoded in source, or reused across different "
        "audiences, issuers, or purposes."
    ),
    "missing_claim_validation": (
        "The application fails to validate token validity-window claims "
        "(exp/nbf) or the aud/iss claims, allowing an expired, replayed, or "
        "cross-audience/cross-issuer token to be accepted."
    ),
    "stateless_session_without_revocation": (
        "JWTs are used as a general-purpose stateless session mechanism "
        "without a workable invalidation/revocation strategy, undermining the "
        "'stateless' benefit they were chosen for."
    ),
    "revocation_list_malleability": (
        "A JWT denylist/revocation check is keyed on the raw token string or a "
        "naive hash of it, which can be bypassed via JWT malleability (e.g. "
        "non-strict parsing or ECDSA signature malleability) producing an "
        "alternative valid representation of a revoked token."
    ),
    "sensitive_data_in_claims": (
        "Sensitive or confidential information is placed directly in a signed "
        "(but unencrypted) JWT payload, relying on the signature for integrity "
        "while mistakenly assuming it also provides confidentiality."
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
