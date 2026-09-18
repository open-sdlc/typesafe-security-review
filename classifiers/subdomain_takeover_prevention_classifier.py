"""Subdomain Takeover Prevention Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Subdomain Takeover Prevention Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Subdomain_Takeover_Prevention_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python subdomain_takeover_prevention_classifier.py "some text to classify"
    python subdomain_takeover_prevention_classifier.py --file path/to/content.txt
    echo "some text" | python subdomain_takeover_prevention_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Subdomain Takeover Prevention Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Subdomain_Takeover_Prevention_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's mechanism, impact, and DNS
# record-type sections. Each description is written so Jev (the TypeSafe
# model) can distinguish it from neighboring categories -- be specific about
# what does and does not count.
CATEGORIES = {
    "dangling_dns_record": (
        "A DNS record (typically CNAME, but also A) points to a cloud resource or "
        "third-party service that has since been deprovisioned or deleted, leaving the "
        "record 'dangling' and claimable by anyone who registers the same resource name."
    ),
    "ns_delegation_takeover": (
        "An NS record delegates a subdomain's DNS zone to a third-party DNS provider whose "
        "account has been closed, allowing anyone who creates a new account at that "
        "provider to potentially claim the delegated zone and control all its records."
    ),
    "mx_record_email_interception": (
        "An MX record points to a deprovisioned mail service, allowing an attacker to "
        "receive email addressed to the subdomain, including password reset messages or "
        "domain-validation challenge emails."
    ),
    "session_cookie_theft_via_subdomain": (
        "A taken-over subdomain is used to steal cookies scoped to the parent domain (e.g. "
        "cookies set on .example.com are also sent to attacker-controlled.example.com)."
    ),
    "csp_bypass_via_trusted_wildcard": (
        "A hijacked subdomain is used to bypass a Content Security Policy that trusts a "
        "wildcard source such as *.example.com, allowing the attacker to load or execute "
        "content the CSP was meant to block."
    ),
    "phishing_on_trusted_domain": (
        "A takeover is used to host a convincing phishing page on a subdomain that users "
        "or customers already trust, rather than on an obviously unrelated domain."
    ),
    "oauth_sso_redirect_hijack": (
        "A taken-over subdomain is listed as a valid OAuth or SSO redirect URI, allowing the "
        "attacker to intercept authorization codes or tokens intended for the legitimate "
        "application."
    ),
    "fraudulent_tls_certificate_issuance": (
        "An attacker who controls a dangling subdomain (or its MX records) completes "
        "domain-validation (DV) challenges to obtain a legitimate TLS certificate for that "
        "subdomain from a public Certificate Authority."
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
