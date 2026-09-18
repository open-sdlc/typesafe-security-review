"""Automotive Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Automotive Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Automotive_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python automotive_security_classifier.py "some text to classify"
    python automotive_security_classifier.py --file path/to/content.txt
    echo "some text" | python automotive_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Automotive Security Cheat Sheet"
CHEATSHEET_URL = "https://cheatsheetseries.owasp.org/cheatsheets/Automotive_Security_Cheat_Sheet.html"

# Sub-categories drawn from the cheat sheet's key sections / named risks /
# recommendations. Each description is written so Jev (the TypeSafe model)
# can distinguish it from neighboring categories -- be specific about what
# does and does not count.
CATEGORIES = {
    "weak_can_bus_protocol": (
        "A vehicle communication protocol such as CAN (Controller Area Network) "
        "lacks adequate authentication or encryption, allowing interception or "
        "injection of unauthorized commands affecting critical systems like "
        "brakes or steering."
    ),
    "insecure_ota_updates": (
        "Over-the-air firmware update mechanisms lack proper authentication and "
        "encryption, allowing an attacker to spoof an update server and deliver "
        "malicious firmware."
    ),
    "insecure_telematics_cloud_link": (
        "A telematics unit connecting the vehicle to cloud services has "
        "insufficient API security, letting an attacker access sensitive vehicle "
        "data or remotely manipulate vehicle settings."
    ),
    "software_supply_chain_vulnerability": (
        "A vehicle's infotainment or control system relies on a third-party "
        "software component or library with a known vulnerability that can be "
        "exploited for arbitrary code execution."
    ),
    "physical_access_exploit": (
        "An attacker with physical access to the vehicle (e.g. via the OBD-II "
        "diagnostic port) connects a malicious device to alter vehicle settings "
        "or firmware directly."
    ),
    "inadequate_vehicle_access_control": (
        "Weak or poorly implemented access control lets an unauthorized user (or "
        "a driver without appropriate rights) reach administrative vehicle "
        "functions through a mobile app or interface."
    ),
    "weak_vehicle_authentication": (
        "A vehicle's mobile app or remote-access system uses weak authentication, "
        "such as easily guessable passwords, letting an attacker log in and "
        "change settings or track the vehicle's location."
    ),
    "vehicle_data_privacy_leakage": (
        "Extensive vehicle-collected data (location history, personal "
        "preferences) is transmitted or stored through an inadequately protected "
        "channel, exposing it to eavesdroppers."
    ),
    "insecure_system_integration": (
        "Integrated vehicle systems (infotainment, navigation, control systems) "
        "lack proper isolation, letting a vulnerability in one interconnected "
        "component be leveraged to reach another, more critical one."
    ),
    "legacy_unpatched_vehicle_systems": (
        "An older vehicle model or legacy system continues to run outdated "
        "software with known, unpatched vulnerabilities that an attacker can "
        "exploit to gain control over critical systems."
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
