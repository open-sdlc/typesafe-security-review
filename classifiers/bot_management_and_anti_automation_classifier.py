"""Bot Management and Anti-Automation Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Bot Management and Anti-Automation Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python bot_management_and_anti_automation_classifier.py "some text to classify"
    python bot_management_and_anti_automation_classifier.py --file path/to/content.txt
    echo "some text" | python bot_management_and_anti_automation_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Bot Management and Anti-Automation Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Bot_Management_and_Anti-Automation_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "credential_stuffing_automation": (
        "Automated, large-scale replay of breached username/password pairs "
        "against a login endpoint (OWASP Automated Threat OAT-008 Credential "
        "Stuffing)."
    ),
    "content_or_price_scraping": (
        "Automated, large-scale extraction of content, pricing, or personal data "
        "from pages or APIs (OAT-011 Scraping)."
    ),
    "inventory_scalping_or_hoarding": (
        "Automated bulk purchasing, cart-hoarding, or checkout automation "
        "targeting limited-availability inventory for resale, or adding items to "
        "deplete stock without buying (OAT-005 Scalping / OAT-015 Denial of "
        "Inventory)."
    ),
    "fake_account_creation": (
        "Automated mass signup creating fraudulent, throwaway, or bulk fake "
        "accounts at a registration endpoint (OAT-019 Account Creation)."
    ),
    "card_testing_or_gift_card_cracking": (
        "Automated testing of stolen payment card numbers via low-value "
        "purchases, or brute-forcing gift card, voucher, or coupon codes (OAT-001 "
        "Carding / OAT-002 Token Cracking)."
    ),
    "ad_click_fraud_or_metric_skew": (
        "Automated fake clicks, impressions, or interactions intended to commit "
        "ad fraud or pollute business metrics like A/B tests, recommendations, or "
        "fraud models (OAT-003 Ad Fraud)."
    ),
    "single_bucket_rate_limit_flaw": (
        "A rate limit is implemented as a single bucket keyed on the combination "
        "of IP and username instead of two independent per-username and per-IP "
        "buckets, allowing a single IP to try one password against unlimited "
        "accounts before any limit fires."
    ),
    "captcha_overreliance": (
        "A visible CAPTCHA is used as the sole or primary bot defense rather than "
        "layered signals, even though CAPTCHAs are machine-solvable and can be "
        "outsourced to human solver farms."
    ),
    "excessive_or_undisclosed_fingerprinting": (
        "Client-side device or browser fingerprinting (canvas, WebGL, font "
        "enumeration) is collected without disclosure, consent, minimization, or "
        "a short retention window."
    ),
    "public_api_abuse_without_keys": (
        "A public API lacks per-key quotas, request signing, or tiering, letting "
        "automated clients consume it at unrestricted volume indistinguishable "
        "from legitimate partner traffic."
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
