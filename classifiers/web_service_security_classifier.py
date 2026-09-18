"""Web Service Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Web Service Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python web_service_security_classifier.py "some text to classify"
    python web_service_security_classifier.py --file path/to/content.txt
    echo "some text" | python web_service_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Web Service Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Web_Service_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's rule-based sections covering
# transport, authentication, validation, and availability of SOAP/XML web
# services. Each description is written so Jev (the TypeSafe model) can
# distinguish it from neighboring categories.
CATEGORIES = {
    "transport_confidentiality_gaps": (
        "Content discusses a lack of properly configured TLS for web "
        "service communications, exposing them to eavesdropping or "
        "man-in-the-middle attacks."
    ),
    "weak_server_or_client_authentication": (
        "Content discusses inadequate server authentication (e.g. missing "
        "certificate validation) or weak user/client authentication such as "
        "Basic Authentication without TLS, as opposed to stronger options "
        "like mutual TLS client certificates."
    ),
    "message_integrity_and_confidentiality": (
        "Content discusses ensuring integrity or confidentiality of data at "
        "rest or in transit via mechanisms like XML digital signatures or "
        "strong message-level encryption, rather than relying on transport "
        "security alone."
    ),
    "coarse_and_fine_grained_authorization": (
        "Content discusses whether a web service checks that a client is "
        "authorized to invoke a given method (coarse-grained) and to act on "
        "the specific requested data (fine-grained) on every request, "
        "especially for sensitive actions like password or contact changes."
    ),
    "schema_and_content_validation": (
        "Content discusses validating SOAP/XML payloads against an XML "
        "Schema Definition (XSD), including constraints on maximum length, "
        "character set, and allow-list patterns for parameters."
    ),
    "output_encoding_for_clients": (
        "Content discusses encoding web service output so it is consumed "
        "as data rather than executable script when a client renders it "
        "into an HTML page, directly or via AJAX."
    ),
    "malware_in_attachments": (
        "Content discusses the risk of viruses or malware being attached "
        "to SOAP messages via file attachments, and the need for inline "
        "virus scanning before files are saved to disk."
    ),
    "message_size_dos": (
        "Content discusses denial-of-service risk from unbounded or "
        "excessively large SOAP/web service message sizes overwhelming the "
        "service."
    ),
    "resource_exhaustion_availability": (
        "Content discusses limiting CPU cycles, memory, open files, "
        "network connections, or processes consumed by a web service to "
        "preserve system stability under load or attack."
    ),
    "xml_dos_entity_expansion": (
        "Content discusses XML-specific denial-of-service protections for "
        "web services, such as validating against recursive payloads, "
        "oversized payloads, XML entity expansion, or overlong element/"
        "SOAP action names."
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
