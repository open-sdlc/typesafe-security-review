"""WebSocket Security Cheat Sheet classifier built on the TypeSafe System One API.

Classifies input text against sub-categories drawn from the OWASP
"WebSocket Security Cheat Sheet" cheat sheet:
https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html

Each sub-category is scored independently as a TypeSafe Noul question (does
the input relate to / exhibit this issue?), so a single input can match zero,
one, or several categories at once. All categories are evaluated in one
parallel system_one() call.

Usage:
    python websocket_security_classifier.py "some text to classify"
    python websocket_security_classifier.py --file path/to/content.txt
    echo "some text" | python websocket_security_classifier.py
"""

import argparse
import sys

from typesafe_sdk import Noul, TypeSafeClient

# --- Standard classifier module interface (used by run_all_classifiers.py) ---
CHEATSHEET_NAME = "WebSocket Security Cheat Sheet"
CHEATSHEET_URL = (
    "https://cheatsheetseries.owasp.org/cheatsheets/"
    "WebSocket_Security_Cheat_Sheet.html"
)

# Sub-categories drawn from the cheat sheet's introduction risk list and
# primary defenses sections. Each description is written so Jev (the
# TypeSafe model) can distinguish it from neighboring categories.
CATEGORIES = {
    "cross_site_websocket_hijacking": (
        "Content describes an attacker-controlled website opening a "
        "WebSocket connection to a target application, whose handshake "
        "automatically carries the victim's browser cookies, hijacking an "
        "authenticated WebSocket session (CSWSH)."
    ),
    "missing_origin_validation": (
        "Content discusses a WebSocket server failing to validate the "
        "Origin header on the handshake, or using a denylist, wildcard, or "
        "substring match instead of a strict allowlist of trusted origins."
    ),
    "unencrypted_websocket_transport": (
        "Content discusses the use of unencrypted ws:// WebSocket "
        "connections instead of wss://, exposing connection traffic to "
        "eavesdropping or tampering."
    ),
    "message_injection_payloads": (
        "Content describes WebSocket messages carrying injection payloads "
        "such as XSS, SQL injection, or command injection, or unsafe use of "
        "eval() to parse message data instead of JSON.parse()."
    ),
    "session_and_token_management": (
        "Content discusses WebSocket-specific session handling: validating "
        "or expiring user sessions on long-lived connections, closing "
        "sockets when a session or user logs out, or rotating/refreshing "
        "authentication tokens used over the socket."
    ),
    "message_level_authorization": (
        "Content discusses the assumption that establishing a WebSocket "
        "connection grants unlimited access, contrasted with checking "
        "authorization for each individual action/message sent over an "
        "already-open socket."
    ),
    "websocket_dos_resource_exhaustion": (
        "Content discusses denial-of-service risk from persistent "
        "WebSocket connections: connection flooding, oversized or rapid "
        "message bursts, or the absence of memory/backpressure controls on "
        "the server."
    ),
    "replay_attack_on_messages": (
        "Content describes an attacker resending a previously captured "
        "WebSocket message (a replay attack), and the use of nonces or "
        "timestamps to detect and reject duplicate messages."
    ),
    "service_tunneling_exposure": (
        "Content discusses tunneling internal TCP services such as VNC, "
        "FTP, or SSH over a WebSocket connection, and the risk of exposing "
        "those services to a browser-side attacker via an XSS "
        "vulnerability."
    ),
    "insufficient_websocket_logging": (
        "Content discusses the gap where traditional HTTP access logs only "
        "capture the initial WebSocket upgrade request, missing subsequent "
        "message traffic, authentication failures, and abuse that occur "
        "over the open connection."
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
