"""Choosing and Using Security Questions Cheat Sheet classifier built on the
TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Choosing and Using Security Questions Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python choosing_and_using_security_questions_classifier.py "some text to classify"
    python choosing_and_using_security_questions_classifier.py --file path/to/content.txt
    echo "some text" | python choosing_and_using_security_questions_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Choosing and Using Security Questions Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Choosing_and_Using_Security_Questions_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "weak_guessable_question_answers": (
        "A security question has a small, guessable, or easily researched "
        "answer space, such as date of birth, favorite color, or memorable "
        "date, which an attacker could brute-force or guess without prior "
        "knowledge of the victim."
    ),
    "socially_discoverable_answers": (
        "The answer to a security question could plausibly be obtained by an "
        "attacker from social media, public records, or casual conversation, "
        "e.g. nickname, pet's name, or favorite sports team."
    ),
    "answer_instability_over_time": (
        "The security question's answer is likely to change over time (such "
        "as favorite movie or favorite food), making it unreliable for account "
        "recovery years after the account was created."
    ),
    "non_universal_applicability": (
        "The question assumes a life experience or context that not all users "
        "will have (e.g. owning a first car, having a favorite sports team), "
        "making it inapplicable to a meaningful portion of the user base."
    ),
    "user_authored_question_weakness": (
        "Users are allowed to write their own custom security question, "
        "risking overly weak, guessable, or self-defeating questions such as "
        "one that reveals the password itself."
    ),
    "insecure_answer_storage_or_comparison": (
        "Security question answers are stored in plaintext, with reversible "
        "encryption, or without a secure hashing algorithm, instead of being "
        "treated and protected like passwords."
    ),
    "security_question_reuse_across_sites": (
        "The same security question and answer combination is likely to be "
        "reused by the user across multiple unrelated sites/services, "
        "creating a cross-site credential exposure risk if one site is "
        "breached."
    ),
    "sole_or_primary_authentication_factor_reliance": (
        "Security questions are relied upon as the sole or primary "
        "authentication mechanism, or are treated as if they constitute a "
        "second independent authentication factor (MFA), when they are in "
        "fact the same 'something you know' factor as a password."
    ),
    "account_enumeration_via_recovery_flow": (
        "The forgotten-password or account recovery flow reveals whether an "
        "email/username exists (e.g. by immediately displaying security "
        "questions) before the user has proven ownership of the account, "
        "enabling user enumeration."
    ),
    "missing_lockout_on_repeated_question_changes": (
        "The application allows an attacker unlimited attempts to answer a "
        "security question, or allows the specific question shown to change "
        "between attempts, instead of locking the question and counting "
        "failures toward an account lockout."
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
