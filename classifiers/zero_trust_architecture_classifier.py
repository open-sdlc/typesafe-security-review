"""Zero Trust Architecture Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Zero Trust Architecture Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Zero_Trust_Architecture_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python zero_trust_architecture_classifier.py "some text to classify"
    python zero_trust_architecture_classifier.py --file path/to/content.txt
    echo "some text" | python zero_trust_architecture_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Zero Trust Architecture Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Zero_Trust_Architecture_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's core principles, the modern
# threats it addresses, and its identity/device/network/legacy-system
# guidance. Each description is written so Jev (the TypeSafe model) can
# distinguish it from neighboring categories.
CATEGORIES = {
    "implicit_network_trust": (
        "Content describes treating internal network location as "
        "inherently trustworthy, a 'castle-and-moat' perimeter security "
        "model, instead of verifying every access request regardless of "
        "where it originates."
    ),
    "static_or_permanent_access": (
        "Content describes granting long-lived or permanent access and "
        "permissions, such as standing/always-on admin rights, rather than "
        "short-lived, per-session, just-in-time access that requires "
        "re-authentication."
    ),
    "weak_or_phishable_mfa": (
        "Content discusses authentication relying on weak or phishable "
        "factors such as SMS-based one-time codes, instead of "
        "phishing-resistant methods like FIDO2 hardware security keys or "
        "WebAuthn-based passkeys."
    ),
    "flat_network_lateral_movement": (
        "Content describes a flat, unsegmented internal network that lets "
        "an attacker who compromises one host move laterally to other "
        "systems, contrasted with micro-segmentation that isolates "
        "resources from each other."
    ),
    "device_posture_and_compliance": (
        "Content discusses continuously verifying device health or "
        "compliance, such as patch level, antivirus status, or "
        "certificate-based device identity, before granting or maintaining "
        "access to a resource."
    ),
    "dynamic_risk_based_policy": (
        "Content discusses access decisions that adapt in real time to "
        "contextual risk signals such as user behavior, device posture, "
        "location, or time of day, rather than applying a fixed, static "
        "access rule."
    ),
    "supply_chain_or_identity_attack": (
        "Content describes a modern attack pattern Zero Trust is meant to "
        "counter, such as a supply-chain compromise of trusted software, "
        "stolen-credential or identity-token abuse like pass-the-hash or "
        "golden-ticket attacks, or a direct attack on an API that bypasses "
        "perimeter network defenses."
    ),
    "legacy_system_compatibility_gap": (
        "Content discusses a legacy or unmodifiable system that cannot "
        "support modern authentication, encryption, or fine-grained "
        "network segmentation, requiring a compensating control such as a "
        "security proxy, network isolation zone, or protocol translation "
        "gateway."
    ),
    "insufficient_monitoring_and_logging": (
        "Content discusses gaps in continuous security monitoring, "
        "logging, or behavioral analytics that are needed to detect "
        "anomalies and inform real-time Zero Trust policy decisions."
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
