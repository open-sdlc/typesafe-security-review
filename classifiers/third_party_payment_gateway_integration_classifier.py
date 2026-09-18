"""Third Party Payment Gateway Integration Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Third Party Payment Gateway Integration Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Payment_Gateway_Integration_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python third_party_payment_gateway_integration_classifier.py "some text to classify"
    python third_party_payment_gateway_integration_classifier.py --file path/to/content.txt
    echo "some text" | python third_party_payment_gateway_integration_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Third Party Payment Gateway Integration Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Third_Party_Payment_Gateway_Integration_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "What Can Go Wrong at Each Step"
# and logging/monitoring sections, mapped to the payment flow (cart -> order
# init -> redirect -> payment -> return/verification). Each description is
# written so Jev (the TypeSafe model) can distinguish it from neighboring
# categories -- be specific about what does and does not count.
CATEGORIES = {
    "client_side_price_tampering": (
        "Cart contents such as product prices, discounts, or quantities are trusted from "
        "client-submitted data instead of being recalculated and validated server-side "
        "before the order is created."
    ),
    "unauthenticated_callback_spoofing": (
        "A payment gateway callback or webhook is trusted without verifying its "
        "authenticity (e.g. missing HMAC signature or secret token check), allowing an "
        "attacker to forge a fake 'payment successful' notification."
    ),
    "premature_order_fulfillment": (
        "An order is fulfilled or marked paid based on client-side redirect parameters or "
        "before the payment status has been verified server-to-server directly with the "
        "gateway's API."
    ),
    "callback_replay_attack": (
        "The same valid payment callback/notification can be replayed multiple times to "
        "trigger repeated order fulfillment, such as duplicate shipments or account "
        "credits, because idempotency is not enforced."
    ),
    "untrusted_redirect_parameter_trust": (
        "The merchant application treats parameters in the user's browser redirect back "
        "from the payment gateway as trustworthy proof of payment, even though these are "
        "user-controlled and can be manipulated."
    ),
    "race_condition_duplicate_processing": (
        "Multiple concurrent callback or notification deliveries for the same transaction "
        "are processed without a lock or idempotency check, creating a race condition that "
        "leads to duplicate order processing."
    ),
    "amount_currency_order_mismatch": (
        "The application fails to verify that the callback's amount, currency, and order "
        "ID match what was actually requested, allowing a lower-value or unrelated payment "
        "confirmation to be accepted for a different order."
    ),
    "insufficient_payment_logging_monitoring": (
        "Payment attempts, redirects, and callbacks are not logged with sufficient detail "
        "(timestamps, IPs, raw request data), or there is no alerting on anomalies like "
        "excessive callback attempts or repeated failed payments."
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
