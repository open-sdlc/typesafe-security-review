"""Drone Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"Drone Security Cheat Sheet":
https://cheatsheetseries.owasp.org/cheatsheets/Drone_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python drone_security_classifier.py "some text to classify"
    python drone_security_classifier.py --file path/to/content.txt
    echo "some text" | python drone_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "Drone Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "Drone_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's "Vulnerable Endpoints & Security
# Risks" sections (communication, auth, data, physical, integrity, sensors,
# logging) and the "Secure Communication Protocols" section (MAVLink, CAN,
# ZigBee, Bluetooth, Wi-Fi).
CATEGORIES = {
    "insecure_communication_link": (
        "Data transmitted between the drone (Unmanned Aircraft) and the "
        "Ground Control Station over the Communication Data-Link is not "
        "encrypted, allowing interception of telemetry or control data."
    ),
    "gps_spoofing_or_replay": (
        "The drone's GPS module or command channel is vulnerable to data "
        "spoofing or command replay attacks, allowing an attacker to feed "
        "false position data or resend captured commands."
    ),
    "wifi_authentication_weaknesses": (
        "The drone's Wi-Fi link uses weak authentication, an unprotected "
        "channel, WEP, or lacks 802.11w Management Frame Protection, "
        "enabling deauthentication or unauthorized access attacks."
    ),
    "companion_computer_exposure": (
        "The companion computer/SoC that manages peripherals or telemetry "
        "has open, exploitable ports (e.g. SSH, FTP) or security "
        "misconfigurations."
    ),
    "sensitive_data_at_rest_exposure": (
        "Mission details, sensor logs, edge AI models, or credentials/keys "
        "stored onboard are not encrypted at rest (e.g. no LUKS/gocryptfs/age "
        "encryption), or sensitive data is left in RAM longer than needed."
    ),
    "physical_and_supply_chain_tampering": (
        "The drone has unsecured USB ports or exposed hardware enabling data "
        "theft/tampering if captured, uses components from a compromised "
        "supply chain, or is decommissioned without wiping sensitive data."
    ),
    "firmware_and_boot_integrity_gaps": (
        "The drone lacks Secure Boot/Measured Boot, runs unsigned or "
        "unencrypted firmware, or has no rollback protection, allowing "
        "persistent malicious firmware or configuration modification."
    ),
    "sensor_data_manipulation": (
        "GPS, camera, or altimeter sensor data can be manipulated to feed the "
        "drone's control logic incorrect readings while still reporting "
        "normal values (sensor spoofing)."
    ),
    "protocol_specific_weaknesses": (
        "A drone communication protocol (MAVLink heartbeat/message signing, "
        "CAN bus, ZigBee AES-128/key rotation, Bluetooth pairing mode such as "
        "'Just Works') is used insecurely or without recommended "
        "cryptographic protections."
    ),
    "logging_and_monitoring_gaps": (
        "Security breaches or operational anomalies on the drone or its "
        "integrated camera/telemetry web servers go undetected due to "
        "inadequate logging/monitoring or weak default credentials."
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
