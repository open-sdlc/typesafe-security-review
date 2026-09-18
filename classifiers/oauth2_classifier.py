"""OAuth2 Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"OAuth2 Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python oauth2_classifier.py "some text to classify"
    python oauth2_classifier.py --file path/to/content.txt
    echo "some text" | python oauth2_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "OAuth2 Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "OAuth2_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's numbered recommendations on
# PKCE, token replay, grant types, and client authentication. Each
# description is written so Jev (the TypeSafe model) can distinguish it from
# neighboring categories -- be specific about what does and does not count.
CATEGORIES = {
    "open_redirect_via_redirect_uri": (
        "The client or authorization server forwards the user's browser to "
        "an arbitrary URI taken from a query parameter ('open redirector') "
        "instead of a registered redirect URI, which can be used to "
        "exfiltrate authorization codes or access tokens."
    ),
    "missing_pkce_or_csrf_binding": (
        "The Authorization Code flow is used without PKCE (code_challenge/"
        "code_verifier), or without a one-time 'state'/'nonce' value securely "
        "bound to the user agent, leaving the flow open to authorization code "
        "injection or CSRF."
    ),
    "deprecated_implicit_grant_usage": (
        "The application uses the deprecated Implicit Grant "
        "(`response_type=token`), which returns the access token directly in "
        "the URL fragment and exposes it via browser history, Referer "
        "headers, or proxy/server logs."
    ),
    "unconstrained_bearer_token_reuse": (
        "A bearer access token is accepted across multiple resource servers/ "
        "audiences or is not sender-constrained (no DPoP or mTLS binding), so "
        "anyone who obtains the token value can replay it."
    ),
    "excessive_token_privilege_or_audience": (
        "An issued access token carries broader scopes, resources, or "
        "audience than the minimum required for the specific client request, "
        "violating least-privilege for tokens."
    ),
    "resource_owner_password_credentials_usage": (
        "The application uses the Resource Owner Password Credentials grant, "
        "which requires the client to directly collect and transmit the "
        "user's username and password to obtain a token."
    ),
    "weak_client_authentication": (
        "The authorization server authenticates confidential clients using a "
        "shared/symmetric secret instead of an asymmetric method such as mTLS "
        "or `private_key_jwt`."
    ),
    "insecure_token_transport": (
        "Authorization responses, redirect URIs, or tokens are transmitted "
        "over an unencrypted (plain HTTP) connection instead of TLS."
    ),
    "refresh_token_replay_risk": (
        "Refresh tokens are neither sender-constrained (DPoP/mTLS) nor "
        "rotated on use, so a leaked refresh token can be replayed "
        "indefinitely to mint new access tokens without detection."
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
