"""LDAP Injection Prevention Cheat Sheet classifier built on the TypeSafe
System One API.

Classifies input text against sub-categories drawn from the OWASP
"LDAP Injection Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python ldap_injection_prevention_classifier.py "some text to classify"
    python ldap_injection_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python ldap_injection_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "LDAP Injection Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "LDAP_Injection_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "dn_injection": (
        "Untrusted input is inserted into an LDAP Distinguished Name (DN) "
        "without escaping DN-reserved characters (e.g. \\ # + < > , ; \" ="
        "), allowing an attacker to alter the DN's structure."
    ),
    "search_filter_injection": (
        "Untrusted input is inserted into an LDAP search filter without "
        "RFC 4515 filter escaping, letting an attacker change the filter's "
        "boolean (prefix-notation) logic to retrieve or modify unintended "
        "directory entries."
    ),
    "missing_ldap_encoding_function": (
        "Custom or ad-hoc escaping code is used to sanitize LDAP input "
        "instead of a vetted LDAP encoding library/function (e.g. the OWASP "
        "ESAPI encodeForLDAP/encodeForDN methods or .NET's "
        "Encoder.LdapFilterEncode/LdapDistinguishedNameEncode)."
    ),
    "string_concatenated_ldap_query": (
        "An LDAP query or filter string is built by directly concatenating "
        "untrusted input into the filter (e.g. '(&(uid=' + userInput + "
        "')...)') instead of using a parameterized filter API that supplies "
        "the value out-of-band."
    ),
    "excessive_ldap_bind_privileges": (
        "The LDAP binding account used by the application is granted more "
        "directory privileges than strictly necessary, increasing the "
        "potential impact of a successful LDAP injection."
    ),
    "anonymous_or_unauthenticated_bind": (
        "LDAP bind authentication is bypassed via an anonymous connection or "
        "an unauthenticated bind, undermining bind authentication as a "
        "defense against injection."
    ),
    "missing_allowlist_validation": (
        "Untrusted input destined for an LDAP query is not checked against "
        "an allow-list of permitted characters/values before being used to "
        "build the query."
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
