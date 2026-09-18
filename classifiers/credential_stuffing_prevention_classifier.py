"""Credential Stuffing Prevention Cheat Sheet classifier built on the TypeSafe
System One API.

Classifies input text against sub-categories drawn from the OWASP
"Credential Stuffing Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python credential_stuffing_prevention_classifier.py "some text to classify"
    python credential_stuffing_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python credential_stuffing_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Credential Stuffing Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Credential_Stuffing_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "credential_stuffing_or_password_spraying_attempt": (
        "Automated login attempts test username/password pairs obtained from "
        "a breach of another site (credential stuffing) or test a single weak "
        "password across many different accounts (password spraying), as "
        "opposed to a brute-force attack on one account."
    ),
    "missing_multi_factor_authentication": (
        "The application does not offer or require multi-factor "
        "authentication (MFA/passkeys), which is described as the single most "
        "effective defense against credential stuffing and password "
        "spraying."
    ),
    "missing_risk_based_step_up_authentication": (
        "The application does not require an additional authentication factor "
        "in response to risk signals such as a new device/browser, an "
        "unusual country, a denylisted or anonymized IP, or a login pattern "
        "that looks scripted/bot-like."
    ),
    "missing_captcha_challenge": (
        "The login flow lacks a CAPTCHA or similar human-verification puzzle "
        "that would help distinguish automated credential stuffing tools from "
        "genuine human users."
    ),
    "insufficient_ip_reputation_or_rate_controls": (
        "The application relies on a single, predictable IP-based volume "
        "limit or naive IP blocking rather than layered, graduated controls "
        "that consider distributed/proxy-based attacks, geolocation, or "
        "hosting-provider IP classification."
    ),
    "missing_device_or_connection_fingerprinting": (
        "The application does not use device fingerprinting (screen "
        "resolution, fonts, plugins) or connection fingerprinting (JA3, "
        "HTTP/2 fingerprint, header order) to help identify credential "
        "stuffing tooling masquerading as a normal browser."
    ),
    "predictable_username_enables_credential_reuse": (
        "The application uses the user's email address (or another "
        "predictable identifier) as the login username, making stolen "
        "email/password pairs from other breaches directly reusable in "
        "credential stuffing attacks."
    ),
    "single_step_login_without_friction": (
        "The login process accepts username and password in a single POST "
        "request with no additional step (such as sequential entry or a "
        "required CSRF token fetch), making it trivial for off-the-shelf "
        "credential stuffing tools to automate."
    ),
    "missing_javascript_or_headless_browser_challenge": (
        "The login endpoint does not require JavaScript execution or employ "
        "headless-browser/bot detection techniques, allowing simple scripted "
        "HTTP clients to submit large volumes of login attempts."
    ),
    "missing_attack_degradation_or_metrics": (
        "The application has no mechanism to increase attacker cost over time "
        "(proof-of-work, increasing delays) and does not generate volume "
        "metrics on detected/mitigated login abuse for monitoring purposes."
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
