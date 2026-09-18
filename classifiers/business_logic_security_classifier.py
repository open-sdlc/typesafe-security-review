"""Business Logic Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Business Logic Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python business_logic_security_classifier.py "some text to classify"
    python business_logic_security_classifier.py --file path/to/content.txt
    echo "some text" | python business_logic_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Business Logic Security Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "client_trusted_price_manipulation": (
        "The application accepts a security-relevant value -- price, subtotal, "
        "discount amount, shipping cost, or tax -- directly from the client "
        "instead of recomputing it server-side from trusted data."
    ),
    "workflow_step_skipping": (
        "A multi-step workflow (checkout, signup, KYC, approval) is enforced only "
        "by the UI or a client-controlled hidden field/cookie rather than "
        "explicit server-side state, letting an attacker skip, repeat, or reorder "
        "steps by calling endpoints directly."
    ),
    "race_condition_check_then_act": (
        "A 'check a condition, then act on it' operation -- balance debit, coupon "
        "redemption, seat/slot booking, or one-per-account bonus -- lacks an "
        "atomic transaction or row lock, allowing concurrent requests to both "
        "pass the check and both act."
    ),
    "replay_of_completed_one_time_action": (
        "A one-time operation such as a signup bonus, coupon redemption, or "
        "referral reward can be re-run because completed steps are not marked "
        "done and rejected on a later attempt."
    ),
    "multi_accounting_abuse": (
        "A user creates multiple accounts specifically to repeatedly claim a "
        "one-per-account reward, bonus, or free trial that is only meant to be "
        "granted once per real person."
    ),
    "self_referral_abuse": (
        "A user refers themselves using a second account to fraudulently claim a "
        "referral reward meant to reward invitations to a distinct person."
    ),
    "coupon_or_discount_stacking": (
        "Multiple discounts or promotions meant to be applied individually are "
        "combined (stacked), pushing the final price below the intended floor or "
        "below cost."
    ),
    "missing_ownership_recheck_per_request": (
        "Ownership or permission over a resource is validated only once when it "
        "is first loaded, and subsequent requests referencing that resource are "
        "trusted without re-checking authorization."
    ),
    "unrated_value_dispensing_feature_abuse": (
        "A value-dispensing feature (referral program, promo code, password "
        "reset, free trial) lacks its own feature-specific rate limit, identity "
        "signal, or audit trail, beyond the app's general authentication "
        "controls."
    ),
    "account_existence_enumeration_via_feature": (
        "A feature such as password reset returns different messages or behavior "
        "for a valid versus invalid account, leaking whether a given account "
        "exists."
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
