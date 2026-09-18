"""JAAS Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"JAAS Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/JAAS_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python jaas_classifier.py "some text to classify"
    python jaas_classifier.py --file path/to/content.txt
    echo "some text" | python jaas_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "JAAS Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/JAAS_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "login_module_configuration": (
        "Content relates to a JAAS login configuration file/stanza that "
        "defines which LoginModule(s) to use and their control flags/options "
        "(e.g. 'required', 'debug=true', 'succeeded=true')."
    ),
    "callback_credential_collection": (
        "Content relates to a CallbackHandler gathering user-supplied "
        "credentials (e.g. via NameCallback/PasswordCallback) so they can be "
        "passed to a LoginModule's login() method."
    ),
    "subject_commit_handling": (
        "Content relates to the commit() phase, where principals and public/"
        "private credentials are associated with a Subject after a login "
        "attempt has been verified as successful."
    ),
    "failed_login_abort_handling": (
        "Content relates to the abort() path invoked when authentication "
        "does not succeed, including whether sensitive login state such as "
        "the username/password fields is properly reset."
    ),
    "logout_cleanup": (
        "Content relates to releasing a Subject's principals and credentials "
        "when LoginContext.logout() is called."
    ),
    "multi_module_shared_state": (
        "Content relates to two or more LoginModules configured within a "
        "single LoginContext sharing information with each other via a "
        "sharedState map."
    ),
    "plaintext_credential_exposure": (
        "Content describes a credential (password, key, or token) being "
        "exposed, logged, or stored in plaintext outside of the intended "
        "LoginModule/CallbackHandler authentication flow."
    ),
    "weak_login_module_flag": (
        "Content describes a LoginModule configured with a permissive flag "
        "(e.g. 'sufficient' or 'optional') or a missing/incomplete "
        "verification step that could let authentication succeed without "
        "full credential verification."
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
