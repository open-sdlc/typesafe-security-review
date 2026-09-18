"""Secure Product Design Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Secure Product Design Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python secure_product_design_classifier.py "some text to classify"
    python secure_product_design_classifier.py --file path/to/content.txt
    echo "some text" | python secure_product_design_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Secure Product Design Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "missing_least_privilege_or_separation_of_duties": (
        "A user, service, or process is granted more access than the minimum "
        "needed for its job, or a single actor controls an entire transaction end "
        "to end without separation of duties."
    ),
    "insufficient_defense_in_depth": (
        "The design relies on a single security control as the sole safeguard for "
        "an asset, rather than multiple independent layers (network, application, "
        "data) that could each catch a failure of another."
    ),
    "zero_trust_violation": (
        "A request, device, or internal network segment is implicitly trusted "
        "without continuous authentication/authorization, contrary to a verify- "
        "every-request zero-trust model."
    ),
    "unvetted_component_selection": (
        "A third-party library, service, or external dependency is adopted during "
        "product design without reviewing its security posture, licensing, or "
        "maintenance status."
    ),
    "insecure_default_configuration": (
        "A system or component is not secure by default, requiring manual, easy- "
        "to-miss hardening steps before it reaches a safe configuration."
    ),
    "missing_threat_modeling_context": (
        "A feature or product decision is made without first considering the "
        "application's place in the business, the sensitivity of data it will "
        "hold, or the resulting risk profile."
    ),
    "insecure_coding_fundamentals_gap": (
        "Code lacks basic secure-coding fundamentals: missing input validation, "
        "hardcoded secrets, weak cryptography, or error handling that leaks "
        "internal details."
    ),
    "fail_insecure_behavior": (
        "A system is designed to fail open or expose additional attack surface "
        "when it malfunctions, rather than failing to a secure, well-understood "
        "default state."
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
