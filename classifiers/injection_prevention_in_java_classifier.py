"""Injection Prevention in Java Cheat Sheet classifier built on the TypeSafe
System One API.

Classifies input text against sub-categories drawn from the OWASP
"Injection Prevention in Java Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html

NOTE: This page has been merged upstream and now simply redirects to the
"Injection Prevention in Java" section of the Java Security Cheat Sheet
(https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html#injection-prevention-in-java).
The categories below were derived by fetching that redirect target's
Injection Prevention in Java section (SQL, JPA, OS command, XPath, HTML/JS,
NoSQL, LDAP and Log injection).

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python injection_prevention_in_java_classifier.py "some text to classify"
    python injection_prevention_in_java_classifier.py --file path/to/content.txt
    echo "some text" | python injection_prevention_in_java_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Injection Prevention in Java Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Injection_Prevention_in_Java_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "sql_injection_java": (
        "A SQL query is built via string concatenation of untrusted input "
        "instead of using a Java PreparedStatement or CallableStatement with "
        "bound parameters (e.g. setString/setInt), letting attacker input "
        "change the query's structure."
    ),
    "jpa_injection": (
        "A JPA/JPQL query string is built via string concatenation of "
        "untrusted input instead of using named or positional parameter "
        "binding with the Java Persistence API's Query/EntityManager."
    ),
    "os_command_injection_java": (
        "Untrusted input is used to build and execute an OS-level command in "
        "Java (e.g. via Runtime.exec or ProcessBuilder) instead of using a "
        "safe Java API alternative that avoids shelling out (e.g. "
        "InetAddress.isReachable for a ping-like check)."
    ),
    "xpath_injection_java": (
        "An XPath expression is built via string concatenation of untrusted "
        "input instead of using a javax.xml.xpath XPathVariableResolver to "
        "bind parameters into the expression safely."
    ),
    "html_output_injection_java": (
        "Untrusted data is written into an HTTP response/HTML page without "
        "strict allow-list input validation and without using an HTML "
        "sanitizing/encoding library (e.g. OWASP Java HTML Sanitizer or the "
        "OWASP Java Encoder) before output."
    ),
    "nosql_injection_java": (
        "Untrusted input is used to build a NoSQL database API call "
        "expression (e.g. MongoDB) without checking for special characters "
        "meaningful to that API (' \" \\ ; { } $) or without using the "
        "database's query-builder API to construct the expression."
    ),
    "ldap_injection_java": (
        "Untrusted input is used to build an LDAP query, search filter, or "
        "distinguished name in a Java application without applying the "
        "correct LDAP-specific escaping for that context."
    ),
    "log_injection_java": (
        "Untrusted data is written directly into an unstructured application "
        "log message (e.g. via string concatenation) instead of using "
        "structured JSON logging and parameterized logger calls (e.g. SLF4J/"
        "Log4j '{}' placeholders), enabling CRLF-based log forging."
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
