"""Network Segmentation Cheat Sheet classifier built on the TypeSafe System
One API.

Classifies input text against sub-categories drawn from the OWASP
"Network Segmentation Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Network_Segmentation_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python network_segmentation_classifier.py "some text to classify"
    python network_segmentation_classifier.py --file path/to/content.txt
    echo "some text" | python network_segmentation_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Network Segmentation Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Network_Segmentation_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "flat_network_no_zones": (
        "The network is a single flat segment without distinct FRONTEND, "
        "MIDDLEWARE, and BACKEND security zones separated by firewalls, so "
        "compromising one component gives an attacker reach across the whole "
        "system."
    ),
    "direct_frontend_to_backend_access": (
        "A frontend component (load balancer, web server, web cache) is "
        "allowed to reach a backend component (database, LDAP directory, key "
        "store, file server) directly, bypassing the middleware application "
        "layer."
    ),
    "cross_service_lateral_movement": (
        "Traffic is allowed between the FRONTEND or MIDDLEWARE segments of "
        "two different information systems/services, enabling an attacker who "
        "compromises one service to move laterally into another."
    ),
    "middleware_to_foreign_backend_access": (
        "A middleware application segment of one service is allowed to reach "
        "the BACKEND segment (e.g. database) belonging to a different "
        "service, bypassing that other service's own application layer."
    ),
    "unrestricted_egress_to_internet": (
        "Servers in the FRONTEND or MIDDLEWARE zones have broad, unrestricted "
        "outbound access to the Internet, which could be used for "
        "command-and-control (C2) callbacks after a compromise."
    ),
    "missing_log_isolation": (
        "Application or security logs are stored only on the same system that "
        "generates them rather than forwarded to a separate, append-only log "
        "segment/server, allowing an attacker who compromises the system to "
        "tamper with or erase its own logs."
    ),
    "undocumented_firewall_policy": (
        "There is no written network security policy describing the allowed "
        "firewall rules and basic network access, leaving network "
        "administrators, auditors, and developers without a shared reference "
        "for what access is permitted."
    ),
    "overly_broad_cicd_or_monitoring_access": (
        "CI/CD systems or IT monitoring tools (e.g. a build server or a "
        "monitoring platform like Zabbix) are granted network access broader "
        "than the specific, documented permissions they require."
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
